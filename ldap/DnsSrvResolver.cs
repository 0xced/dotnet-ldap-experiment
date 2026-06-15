using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ldap;

public sealed class DnsSrvResolver(IPAddress dnsServer, int port = 53)
{
    // ReSharper disable InconsistentNaming
    private const ushort IN = 1;
    private const ushort SRV = 33;
    // ReSharper restore InconsistentNaming

    private readonly IPEndPoint _dnsServer = new(dnsServer, port);

    public async Task<IReadOnlyList<SrvRecord>> QuerySrvAsync(string fqdn, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fqdn);

        var query = BuildQuery(fqdn);
        using var response = await QueryTcpAsync(query, cancellationToken);
        return ParseSrvResponse(response.Memory, query.Id);
    }

    private async Task<IMemoryOwner<byte>> QueryTcpAsync(DnsQueryPacket query, CancellationToken cancellationToken)
    {
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(_dnsServer.Address, _dnsServer.Port, cancellationToken);

        await using var stream = tcp.GetStream();

        await stream.WriteUInt16Async(Convert.ToUInt16(query.Buffer.Length), cancellationToken);
        await stream.WriteAsync(query.Buffer, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var responseLength = await stream.ReadUInt16Async(cancellationToken);
        var response = MemoryPool<byte>.Shared.Rent(responseLength);
        await stream.ReadExactlyAsync(response.Memory[..responseLength], cancellationToken);

        return response;
    }

    private static DnsQueryPacket BuildQuery(string fqdn)
    {
        var buffer = new ArrayBufferWriter<byte>(initialCapacity: 512);

        var messageId = Convert.ToUInt16(Random.Shared.Next(ushort.MaxValue + 1));

        // Header
        buffer.WriteUInt16(messageId);
        buffer.WriteUInt16(0x0100); // RD (Recursion Desired)
        buffer.WriteUInt16(1);      // QDCOUNT
        buffer.WriteUInt16(0);      // ANCOUNT
        buffer.WriteUInt16(0);      // NSCOUNT
        buffer.WriteUInt16(0);      // ARCOUNT

        // Name
        buffer.WriteQName(fqdn);

        // Footer
        buffer.WriteUInt16(SRV);
        buffer.WriteUInt16(IN);

        return new DnsQueryPacket(messageId, buffer.WrittenMemory);
    }

    private static IReadOnlyList<SrvRecord> ParseSrvResponse(Memory<byte> message, ushort expectedId)
    {
        var reader = new DnsMessageReader(message);

        // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
        var id = reader.ReadUInt16();
        if (id != expectedId)
            throw new InvalidDataException($"DNS response ID mismatch. Expected: {expectedId}, actual: {id}");

        var flags = reader.ReadUInt16();
        var qdCount = reader.ReadUInt16();
        var anCount = reader.ReadUInt16();
        _ = reader.ReadUInt16(); // nsCount
        _ = reader.ReadUInt16(); // arCount

        var isResponse = (flags & 0x8000) != 0;
        if (!isResponse)
            throw new InvalidDataException("Not a DNS response.");

        var responseCode = flags & 0x000F;
        if (responseCode != 0)
            throw new DnsQueryException($"DNS server returned error code {responseCode}.", responseCode);

        // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
        for (var i = 0; i < qdCount; i++)
        {
            _ = reader.ReadQName();
            _ = reader.ReadUInt16(); // QTYPE
            _ = reader.ReadUInt16(); // QCLASS
        }

        var results = new List<SrvRecord>();

        // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
        for (var i = 0; i < anCount; i++)
        {
            _ = reader.ReadQName(); // NAME
            _ = reader.ReadUInt16(); // TYPE (SRV)
            _ = reader.ReadUInt16(); // CLASS (IN)
            _ = reader.ReadUInt32(); // TTL
            _ = reader.ReadUInt16(); // RDLENGTH

            var priority = reader.ReadUInt16();
            var weight = reader.ReadUInt16();
            var port = reader.ReadUInt16();
            var target = reader.ReadQName();

            results.Add(new SrvRecord(Target: target, Port: port, Priority: priority, Weight: weight));
        }

        return results.OrderBy(r => r.Priority).ThenByDescending(r => r.Weight).ToArray();
    }

    private readonly record struct DnsQueryPacket(ushort Id, ReadOnlyMemory<byte> Buffer);
}

public sealed record SrvRecord(string Target, int Port, int Priority, int Weight);

public sealed class DnsQueryException(string message, int responseCode) : Exception(message)
{
    public int ResponseCode { get; } = responseCode;
}

internal sealed class DnsMessageReader(Memory<byte> buffer)
{
    private int _position;

    public ushort ReadUInt16()
    {
        EnsureAvailable(2);
        var value = BinaryPrimitives.ReadUInt16BigEndian(buffer.Span.Slice(_position, 2));
        _position += 2;
        return value;
    }

    public uint ReadUInt32()
    {
        EnsureAvailable(4);
        var value = BinaryPrimitives.ReadUInt32BigEndian(buffer.Span.Slice(_position, 4));
        _position += 4;
        return value;
    }

    public string ReadQName()
    {
        var originalPosition = _position;
        var jumped = false;
        var jumpCount = 0;
        var labels = new StringBuilder(capacity: 512);

        while (true)
        {
            EnsureAvailable(1);
            var length = buffer.Span[_position];

            // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            if ((length & 0xC0) == 0xC0)
            {
                EnsureAvailable(2);
                var pointer = ((length & 0x3F) << 8) | buffer.Span[_position + 1];

                if (!jumped)
                {
                    originalPosition = _position + 2;
                }

                _position = pointer;
                jumped = true;

                jumpCount++;
                if (jumpCount > 16)
                    throw new InvalidDataException("Too many DNS compression jumps.");

                continue;
            }

            _position++;

            if (length == 0)
                break;

            EnsureAvailable(length);
            var label = Encoding.ASCII.GetString(buffer.Span.Slice(_position, length));
            labels.Append(label);
            labels.Append('.');
            _position += length;
        }

        if (jumped)
        {
            _position = originalPosition;
        }

        return labels.ToString();
    }

    private void EnsureAvailable(int count)
    {
        if (_position < 0 || _position + count > buffer.Length)
            throw new InvalidDataException("Unexpected end of DNS message.");
    }
}

internal static class BufferWriterExtensions
{
    extension(IBufferWriter<byte> writer)
    {
        public void WriteQName(string fqdn)
        {
            foreach (var label in fqdn.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                var labelBytes = Encoding.ASCII.GetBytes(label);
                if (labelBytes.Length is 0 or > 63)
                    throw new ArgumentException($"Invalid DNS label '{label}'. Length must be > 0 and < 64", nameof(fqdn));

                writer.WriteByte(Convert.ToByte(labelBytes.Length));
                writer.Write(labelBytes);
            }

            writer.WriteByte(0);
        }

        public void WriteUInt16(ushort value)
        {
            Span<byte> span = stackalloc byte[sizeof(ushort)];
            BinaryPrimitives.WriteUInt16BigEndian(span, value);
            writer.Write(span);
        }

        private void WriteByte(byte value)
        {
            Span<byte> span = stackalloc byte[sizeof(byte)];
            span[0] = value;
            writer.Write(span);
        }
    }
}

internal static class StreamBigEndianExtensions
{
    private static readonly Memory<byte> buffer = new byte[sizeof(ushort)];

    extension(Stream stream)
    {
        public async Task<ushort> ReadUInt16Async(CancellationToken cancellationToken)
        {
            await stream.ReadExactlyAsync(buffer, cancellationToken);
            return BinaryPrimitives.ReadUInt16BigEndian(buffer.Span);
        }

        public async Task WriteUInt16Async(ushort value, CancellationToken cancellationToken)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Span, value);
            await stream.WriteAsync(buffer, cancellationToken);
        }
    }
}