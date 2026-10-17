// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Tmds.DBus.Protocol;

namespace ArcForges.Security.Secrets;

/// <summary>
/// The freedesktop Secret Service (<c>org.freedesktop.secrets</c>) over the session D-Bus: one item per key in the default
/// collection, with the attributes <c>{application: arcforges, name: &lt;key&gt;}</c>. A locked collection is unlocked through the
/// desktop keyring's prompt; a dismissed or unanswered prompt fails the operation. The value crosses the bus encrypted
/// (<c>dh-ietf1024-sha256-aes128-cbc-pkcs7</c>) unless the service supports only <c>plain</c>.
/// </summary>
/// <remarks>
/// Each operation opens its own connection and session and closes them afterwards, so the store holds no bus state between calls.
/// The Secret Service is shared by every process of the same user, so the store declares <see cref="SecretStoreIsolation.SameUserShared"/>.
/// </remarks>
[SupportedOSPlatform("linux")]
internal sealed class SecretServiceSecretStore : ISecretBackingStore
{
    internal const string ApplicationAttribute = "application";
    internal const string ApplicationValue = "arcforges";
    internal const string NameAttribute = "name";

    private readonly string _address;
    private readonly SecretServiceOptions _options;

    private SecretServiceSecretStore(string address, SecretServiceOptions options)
    {
        _address = address;
        _options = options;
    }

    public SecretStoreIsolation Isolation => SecretStoreIsolation.SameUserShared;

    public static SecretStoreProtection Protection => SecretStoreProtection.OsSecretStore;

    /// <summary>
    /// The backend is available when a session bus is configured, it accepts a connection, <c>org.freedesktop.secrets</c> opens a
    /// session on it (D-Bus activation may start the desktop keyring) and it has a default collection. A keyring without a default
    /// collection (for example gnome-keyring started headless in a fresh home, without a login keyring) is unavailable: the store
    /// never creates a collection, because that prompts for a new keyring password. Locked collections are not unlocked here.
    /// </summary>
    internal static bool TryOpen(SecretServiceOptions options, [NotNullWhen(true)] out SecretServiceSecretStore? store,
        [NotNullWhen(false)] out string? unavailableReason)
    {
        ArgumentNullException.ThrowIfNull(options);
        return TryOpen(options.BusAddress ?? ResolveSessionBusAddress(), options, out store, out unavailableReason);
    }

    /// <summary>The session bus of the process environment, as libdbus, sd-bus and GDBus find it; <see langword="null"/> when there is none.</summary>
    internal static string? ResolveSessionBusAddress() => ResolveSessionBusAddress(
        Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS"), Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR"));

    /// <summary>
    /// <c>DBUS_SESSION_BUS_ADDRESS</c> when set; otherwise the per-user bus socket <c>$XDG_RUNTIME_DIR/bus</c> when it exists
    /// (systemd user sessions). No X11 or autolaunch discovery: a node without either has no session bus.
    /// </summary>
    internal static string? ResolveSessionBusAddress(string? sessionBusVariable, string? runtimeDirectory)
    {
        if (!string.IsNullOrWhiteSpace(sessionBusVariable)) return sessionBusVariable;
        if (string.IsNullOrEmpty(runtimeDirectory) || !Path.IsPathFullyQualified(runtimeDirectory)) return null;
        string socket = Path.Combine(runtimeDirectory, "bus");
        return File.Exists(socket) ? "unix:path=" + socket : null;
    }

    /// <summary>As <see cref="TryOpen(SecretServiceOptions, out SecretServiceSecretStore?, out string?)"/> with the bus address already resolved.</summary>
    internal static bool TryOpen(string? address, SecretServiceOptions options, [NotNullWhen(true)] out SecretServiceSecretStore? store,
        [NotNullWhen(false)] out string? unavailableReason)
    {
        ArgumentNullException.ThrowIfNull(options);
        // The test tripwire decides before any bus call, and its refusal is never an unavailable backend.
        OsSecretStoreGuard.ThrowIfSecretServiceDenied(options.BusAddress, address);
        store = null;
        if (string.IsNullOrEmpty(address))
        {
            unavailableReason = "No session D-Bus is configured (DBUS_SESSION_BUS_ADDRESS is unset and no $XDG_RUNTIME_DIR/bus exists).";
            return false;
        }

        bool hasDefaultCollection;
        try
        {
            hasDefaultCollection = Run(async cancellationToken =>
            {
                using var session = await SecretServiceSession.OpenAsync(address, options, plainOnly: true, cancellationToken)
                    .ConfigureAwait(false);
                return await session.HasDefaultCollectionAsync(cancellationToken).ConfigureAwait(false);
            }, options);
        }
        catch (Exception exception) when (IsUnavailable(exception))
        {
            unavailableReason = "The Secret Service is not available on the session bus (" + exception.GetType().Name + ": "
                + exception.Message + ").";
            return false;
        }

        if (!hasDefaultCollection)
        {
            unavailableReason = "The Secret Service on the session bus has no default collection (ReadAlias(\"default\") is \"/\"), "
                + "so it cannot hold credentials without creating a keyring; the store never creates one.";
            return false;
        }

        store = new SecretServiceSecretStore(address, options);
        unavailableReason = null;
        return true;
    }

    public void Write(string opaqueTarget, ReadOnlySpan<byte> secret)
    {
        Guard();
        SecretStoreKey.Validate(opaqueTarget, nameof(opaqueTarget));
        SecretStoreKey.ValidateValue(secret, nameof(secret));
        byte[] owned = secret.ToArray();
        try
        {
            _ = Run(async cancellationToken =>
            {
                using var session = await OpenAsync(cancellationToken).ConfigureAwait(false);
                await session.WriteAsync(opaqueTarget, owned, cancellationToken).ConfigureAwait(false);
                return true;
            }, _options);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(owned);
        }
    }

    public byte[]? Read(string opaqueTarget)
    {
        Guard();
        SecretStoreKey.Validate(opaqueTarget, nameof(opaqueTarget));
        return Run(async cancellationToken =>
        {
            using var session = await OpenAsync(cancellationToken).ConfigureAwait(false);
            return await session.ReadAsync(opaqueTarget, cancellationToken).ConfigureAwait(false);
        }, _options);
    }

    public bool Delete(string opaqueTarget)
    {
        Guard();
        SecretStoreKey.Validate(opaqueTarget, nameof(opaqueTarget));
        return Run(async cancellationToken =>
        {
            using var session = await OpenAsync(cancellationToken).ConfigureAwait(false);
            return await session.DeleteAsync(opaqueTarget, cancellationToken).ConfigureAwait(false);
        }, _options);
    }

    /// <summary>Whether a session of this store's service encrypts values on the bus (for tests and diagnostics).</summary>
    internal bool NegotiatesEncryptedTransport()
    {
        Guard();
        return Run(async cancellationToken =>
        {
            using var session = await OpenAsync(cancellationToken).ConfigureAwait(false);
            return session.IsEncrypted;
        }, _options);
    }

    // Every operation re-checks the tripwire with the address this store was opened with, before its connection.
    private void Guard() => OsSecretStoreGuard.ThrowIfSecretServiceDenied(_options.BusAddress, _address);

    private Task<SecretServiceSession> OpenAsync(CancellationToken cancellationToken) =>
        SecretServiceSession.OpenAsync(_address, _options, plainOnly: false, cancellationToken);

    // Only failures that mean "no usable bus or service": D-Bus connection and error replies, socket and I/O errors, and the
    // bounded timeouts. Anything else (for example an InvalidOperationException from a defect) propagates instead of silently
    // selecting the weaker file fallback.
    private static bool IsUnavailable(Exception exception) => exception is DBusExceptionBase or TimeoutException or IOException
        or SocketException or OperationCanceledException;

    // The store's contract is synchronous. The bus work runs on the thread pool, so a caller's synchronization context is never
    // captured, and every step is bounded: each call by CallTimeout, a prompt by PromptTimeout, the whole operation by both.
    private static T Run<T>(Func<CancellationToken, Task<T>> operation, SecretServiceOptions options)
    {
        TimeSpan overall = options.CallTimeout * 12 + options.PromptTimeout;
        using var cancellation = new CancellationTokenSource(overall);
        var task = Task.Run(() => operation(cancellation.Token), CancellationToken.None);
        try
        {
            return task.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            throw new TimeoutException("The Secret Service did not complete the operation in time.");
        }
    }
}

/// <summary>One connection and one Secret Service session; disposed after each store operation.</summary>
[SupportedOSPlatform("linux")]
internal sealed class SecretServiceSession : IDisposable
{
    private const string ServiceName = "org.freedesktop.secrets";
    private const string ServicePath = "/org/freedesktop/secrets";
    private const string ServiceInterface = "org.freedesktop.Secret.Service";
    private const string CollectionInterface = "org.freedesktop.Secret.Collection";
    private const string ItemInterface = "org.freedesktop.Secret.Item";
    private const string SessionInterface = "org.freedesktop.Secret.Session";
    private const string PromptInterface = "org.freedesktop.Secret.Prompt";
    private const string NoObject = "/";
    private const string DefaultAlias = "default";
    private const string PlainAlgorithm = "plain";
    private const string NotSupportedError = "org.freedesktop.DBus.Error.NotSupported";
    private const string ContentType = "application/octet-stream";
    private const string LabelProperty = "org.freedesktop.Secret.Item.Label";
    private const string AttributesProperty = "org.freedesktop.Secret.Item.Attributes";

    private readonly DBusConnection _connection;
    private readonly SecretServiceOptions _options;
    private string? _sessionPath;
    private byte[]? _key;

    private SecretServiceSession(DBusConnection connection, SecretServiceOptions options)
    {
        _connection = connection;
        _options = options;
    }

    internal bool IsEncrypted => _key is not null;

    internal static async Task<SecretServiceSession> OpenAsync(string address, SecretServiceOptions options, bool plainOnly,
        CancellationToken cancellationToken)
    {
        var session = new SecretServiceSession(new DBusConnection(address), options);
        try
        {
            await session._connection.ConnectAsync().AsTask().WaitAsync(options.CallTimeout, cancellationToken).ConfigureAwait(false);
            await session.NegotiateAsync(plainOnly, cancellationToken).ConfigureAwait(false);
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    internal async Task WriteAsync(string key, byte[] secret, CancellationToken cancellationToken)
    {
        string collection = await UnlockDefaultCollectionAsync(cancellationToken).ConfigureAwait(false);
        var (parameters, value) = Encode(secret);
        try
        {
            var (item, prompt) = await CallAsync(CreateItemMessage(collection, key, parameters, value), ReadTwoPaths, cancellationToken)
                .ConfigureAwait(false);
            if (item == NoObject)
            {
                if (prompt == NoObject) throw new InvalidOperationException("The Secret Service did not create the item.");
                if ((await PromptAsync(prompt, cancellationToken).ConfigureAwait(false)).Dismissed)
                {
                    throw new UnauthorizedAccessException("The keyring prompt was dismissed; the secret was not stored.");
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    internal async Task<byte[]?> ReadAsync(string key, CancellationToken cancellationToken)
    {
        string collection = await UnlockDefaultCollectionAsync(cancellationToken).ConfigureAwait(false);
        string[] items = await CallAsync(SearchItemsMessage(collection, key), ReadPaths, cancellationToken).ConfigureAwait(false);
        if (items.Length == 0) return null;
        if (items.Length > 1)
        {
            throw new InvalidDataException(
                "More than one Secret Service item carries this ArcForges key; delete the key and store it again.");
        }

        var (parameters, value) = await CallAsync(GetSecretMessage(items[0]), ReadSecret, cancellationToken).ConfigureAwait(false);
        return Decode(parameters, value);
    }

    internal async Task<bool> DeleteAsync(string key, CancellationToken cancellationToken)
    {
        string collection = await UnlockDefaultCollectionAsync(cancellationToken).ConfigureAwait(false);
        string[] items = await CallAsync(SearchItemsMessage(collection, key), ReadPaths, cancellationToken).ConfigureAwait(false);
        foreach (string item in items)
        {
            string prompt = await CallAsync(DeleteMessage(item), ReadPath, cancellationToken).ConfigureAwait(false);
            if (prompt != NoObject && (await PromptAsync(prompt, cancellationToken).ConfigureAwait(false)).Dismissed)
            {
                throw new UnauthorizedAccessException("The keyring prompt was dismissed; the secret was not deleted.");
            }
        }

        return items.Length > 0;
    }

    public void Dispose()
    {
        if (_sessionPath is not null)
        {
            // The service also closes a session when its connection goes away; this only says so first.
            _ = _connection.TrySendMessage(CloseSessionMessage(_sessionPath));
            _sessionPath = null;
        }

        _connection.Dispose();
        if (_key is not null) CryptographicOperations.ZeroMemory(_key);
        _key = null;
    }

    private async Task NegotiateAsync(bool plainOnly, CancellationToken cancellationToken)
    {
        if (!plainOnly)
        {
            using var exchange = new SecretServiceKeyExchange();
            try
            {
                var (output, path) = await CallAsync(OpenSessionMessage(SecretServiceKeyExchange.Algorithm, exchange.PublicKey),
                    ReadVariantAndPath, cancellationToken).ConfigureAwait(false);
                if (output.Type != VariantValueType.Array || output.ItemType != VariantValueType.Byte)
                {
                    throw new InvalidDataException("The Secret Service returned no public key for the encrypted session.");
                }

                _key = exchange.DeriveKey(output.GetArray<byte>());
                _sessionPath = path;
                return;
            }
            catch (DBusErrorReplyException error) when (error.ErrorName == NotSupportedError)
            {
                // A service that supports only the mandatory "plain" algorithm; the value then crosses the same-user bus as is.
            }
        }

        var (_, plainPath) = await CallAsync(OpenSessionMessage(PlainAlgorithm, publicKey: null), ReadVariantAndPath, cancellationToken)
            .ConfigureAwait(false);
        _sessionPath = plainPath;
    }

    internal async Task<bool> HasDefaultCollectionAsync(CancellationToken cancellationToken) =>
        await CallAsync(ReadAliasMessage(DefaultAlias), ReadPath, cancellationToken).ConfigureAwait(false) != NoObject;

    private async Task<string> UnlockDefaultCollectionAsync(CancellationToken cancellationToken)
    {
        string collection = await CallAsync(ReadAliasMessage(DefaultAlias), ReadPath, cancellationToken).ConfigureAwait(false);
        if (collection == NoObject)
        {
            // Backstop: selection already refuses a service without a default collection, but it can disappear later.
            throw new InvalidOperationException("The Secret Service has no default collection.");
        }

        var (unlocked, prompt) = await CallAsync(UnlockMessage(collection), ReadPathsAndPath, cancellationToken).ConfigureAwait(false);
        if (unlocked.Contains(collection, StringComparer.Ordinal)) return collection;
        if (prompt == NoObject)
        {
            throw new UnauthorizedAccessException("The Secret Service default collection is locked and offers no unlock prompt.");
        }

        if ((await PromptAsync(prompt, cancellationToken).ConfigureAwait(false)).Dismissed)
        {
            throw new UnauthorizedAccessException("The keyring unlock prompt was dismissed; the default collection stays locked.");
        }

        return collection;
    }

    private async Task<(bool Dismissed, VariantValue Result)> PromptAsync(string prompt, CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<(bool Dismissed, VariantValue Result)>(TaskCreationOptions.RunContinuationsAsynchronously);
        using IDisposable watch = await _connection.WatchSignalAsync(ServiceName, prompt, PromptInterface, "Completed", ReadCompleted,
            (Notification<(bool Dismissed, VariantValue Result)> notification) =>
            {
                if (notification.HasValue) completion.TrySetResult(notification.Value);
                else if (notification.Exception is not null) completion.TrySetException(notification.Exception);
            }, ObserverFlags.None, emitOnCapturedContext: false)
            .AsTask().WaitAsync(_options.CallTimeout, cancellationToken).ConfigureAwait(false);
        await _connection.CallMethodAsync(PromptMessage(prompt)).WaitAsync(_options.CallTimeout, cancellationToken).ConfigureAwait(false);
        try
        {
            return await completion.Task.WaitAsync(_options.PromptTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            try
            {
                await _connection.CallMethodAsync(DismissMessage(prompt)).WaitAsync(_options.CallTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (DBusExceptionBase)
            {
            }
            catch (TimeoutException)
            {
            }

            throw new TimeoutException("The desktop keyring prompt was not answered in time and was dismissed.");
        }
    }

    private (byte[] Parameters, byte[] Value) Encode(byte[] secret)
    {
        if (_key is null) return ([], secret.ToArray());
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        using var aes = Aes.Create();
        aes.Key = _key;
        return (iv, aes.EncryptCbc(secret, iv, PaddingMode.PKCS7));
    }

    private byte[] Decode(byte[] parameters, byte[] value)
    {
        byte[] secret;
        if (_key is null)
        {
            if (parameters.Length != 0) throw new InvalidDataException("A plain Secret Service session returned encryption parameters.");
            secret = value;
        }
        else
        {
            if (parameters.Length != 16) throw new InvalidDataException("The Secret Service returned an invalid initialization vector.");
            using var aes = Aes.Create();
            aes.Key = _key;
            try
            {
                secret = aes.DecryptCbc(value, parameters, PaddingMode.PKCS7);
            }
            catch (CryptographicException exception)
            {
                throw new InvalidDataException("The Secret Service returned a value that does not decrypt in this session.", exception);
            }
        }

        if (secret.Length is 0 or > SecretBroker.MaximumSecretBytes)
        {
            CryptographicOperations.ZeroMemory(secret);
            throw new InvalidDataException("The Secret Service item is empty or larger than the secret-store bound.");
        }

        return secret;
    }

    private Task<T> CallAsync<T>(MessageBuffer message, MessageValueReader<T> reader, CancellationToken cancellationToken) =>
        _connection.CallMethodAsync(message, reader).WaitAsync(_options.CallTimeout, cancellationToken);

    private MessageBuffer OpenSessionMessage(string algorithm, byte[]? publicKey)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(ServiceName, ServicePath, ServiceInterface, "OpenSession", "sv", MessageFlags.None);
            writer.WriteString(algorithm);
            if (publicKey is null) writer.WriteVariantString(string.Empty);
            else writer.WriteVariant(VariantValue.Array(publicKey));
            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private MessageBuffer ReadAliasMessage(string alias)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(ServiceName, ServicePath, ServiceInterface, "ReadAlias", "s", MessageFlags.None);
            writer.WriteString(alias);
            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private MessageBuffer UnlockMessage(string collection)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(ServiceName, ServicePath, ServiceInterface, "Unlock", "ao", MessageFlags.None);
            writer.WriteArray(new[] { new ObjectPath(collection) });
            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private MessageBuffer SearchItemsMessage(string collection, string key)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(ServiceName, collection, CollectionInterface, "SearchItems", "a{ss}", MessageFlags.None);
            WriteAttributes(ref writer, key);
            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private MessageBuffer CreateItemMessage(string collection, string key, byte[] parameters, byte[] value)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(ServiceName, collection, CollectionInterface, "CreateItem", "a{sv}(oayays)b", MessageFlags.None);
            var properties = writer.WriteDictionaryStart();
            writer.WriteDictionaryEntryStart();
            writer.WriteString(LabelProperty);
            writer.WriteVariantString("ArcForges " + key);
            writer.WriteDictionaryEntryStart();
            writer.WriteString(AttributesProperty);
            writer.WriteSignature("a{ss}");
            WriteAttributes(ref writer, key);
            writer.WriteDictionaryEnd(properties);
            writer.WriteStructureStart();
            writer.WriteObjectPath(_sessionPath ?? throw new InvalidOperationException("No Secret Service session is open."));
            writer.WriteArray(parameters);
            writer.WriteArray(value);
            writer.WriteString(ContentType);
            writer.WriteBool(true); // replace the item that carries the same attributes
            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private MessageBuffer GetSecretMessage(string item)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(ServiceName, item, ItemInterface, "GetSecret", "o", MessageFlags.None);
            writer.WriteObjectPath(_sessionPath ?? throw new InvalidOperationException("No Secret Service session is open."));
            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private MessageBuffer DeleteMessage(string item) => NoArgumentMessage(item, ItemInterface, "Delete", MessageFlags.None);

    private MessageBuffer DismissMessage(string prompt) => NoArgumentMessage(prompt, PromptInterface, "Dismiss", MessageFlags.None);

    private MessageBuffer CloseSessionMessage(string session) =>
        NoArgumentMessage(session, SessionInterface, "Close", MessageFlags.NoReplyExpected);

    private MessageBuffer PromptMessage(string prompt)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(ServiceName, prompt, PromptInterface, "Prompt", "s", MessageFlags.None);
            writer.WriteString(string.Empty); // no parent window
            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private MessageBuffer NoArgumentMessage(string path, string @interface, string member, MessageFlags flags)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(ServiceName, path, @interface, member, signature: null, flags);
            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static void WriteAttributes(ref MessageWriter writer, string key)
    {
        var attributes = writer.WriteDictionaryStart();
        writer.WriteDictionaryEntryStart();
        writer.WriteString(SecretServiceSecretStore.ApplicationAttribute);
        writer.WriteString(SecretServiceSecretStore.ApplicationValue);
        writer.WriteDictionaryEntryStart();
        writer.WriteString(SecretServiceSecretStore.NameAttribute);
        writer.WriteString(key);
        writer.WriteDictionaryEnd(attributes);
    }

    private static (VariantValue Output, string Path) ReadVariantAndPath(Message message, object? state)
    {
        var reader = message.GetBodyReader();
        var output = reader.ReadVariantValue();
        return (output, reader.ReadObjectPathAsString());
    }

    private static string ReadPath(Message message, object? state)
    {
        var reader = message.GetBodyReader();
        return reader.ReadObjectPathAsString();
    }

    private static string[] ReadPaths(Message message, object? state)
    {
        var reader = message.GetBodyReader();
        return Array.ConvertAll(reader.ReadArrayOfObjectPath(), path => path.ToString());
    }

    private static (string[] Paths, string Path) ReadPathsAndPath(Message message, object? state)
    {
        var reader = message.GetBodyReader();
        string[] paths = Array.ConvertAll(reader.ReadArrayOfObjectPath(), path => path.ToString());
        return (paths, reader.ReadObjectPathAsString());
    }

    private static (string First, string Second) ReadTwoPaths(Message message, object? state)
    {
        var reader = message.GetBodyReader();
        string first = reader.ReadObjectPathAsString();
        return (first, reader.ReadObjectPathAsString());
    }

    private static (byte[] Parameters, byte[] Value) ReadSecret(Message message, object? state)
    {
        var reader = message.GetBodyReader();
        reader.AlignStruct();
        _ = reader.ReadObjectPathAsString();
        byte[] parameters = reader.ReadArrayOfByte();
        byte[] value = reader.ReadArrayOfByte();
        _ = reader.ReadString();
        return (parameters, value);
    }

    private static (bool Dismissed, VariantValue Result) ReadCompleted(Message message, object? state)
    {
        var reader = message.GetBodyReader();
        bool dismissed = reader.ReadBool();
        return (dismissed, reader.ReadVariantValue());
    }
}
