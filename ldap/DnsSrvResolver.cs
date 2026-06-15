using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ldap;

public sealed class DnsSrvResolver(IPAddress dnsServer, int port = 53)
{
    // ReSharper disable once InconsistentNaming
    private const ushort SRV = 33;

    private readonly IPEndPoint _dnsServer = new(dnsServer, port);

    public async Task<IReadOnlyList<SrvRecord>> QuerySrvAsync(string fqdn, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fqdn);

        var query = BuildQuery(fqdn.TrimEnd('.'));

        var response = await QueryUdpAsync(query, cancellationToken);

        if (IsTruncated(response))
        {
            response = await QueryTcpAsync(query, cancellationToken);
        }

        return ParseSrvResponse(response, query.Id);
    }

    private async Task<byte[]> QueryUdpAsync(DnsQueryPacket query, CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.ReceiveTimeout = 5000;
        udp.Client.SendTimeout = 5000;

        await udp.SendAsync(query.Buffer, _dnsServer, cancellationToken);

        try
        {
            var result = await udp.ReceiveAsync(cancellationToken);
            return result.Buffer;
        }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
    }

    private async Task<byte[]> QueryTcpAsync(DnsQueryPacket query, CancellationToken cancellationToken)
    {
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(_dnsServer.Address, _dnsServer.Port, cancellationToken);

        await using var stream = tcp.GetStream();

        var lengthPrefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, Convert.ToUInt16(query.Buffer.Length));

        await stream.WriteAsync(lengthPrefix, cancellationToken);
        await stream.WriteAsync(query.Buffer, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var responseLengthBuffer = new byte[2];
        await ReadExactlyAsync(stream, responseLengthBuffer, cancellationToken);
        var responseLength = BinaryPrimitives.ReadUInt16BigEndian(responseLengthBuffer);

        var response = new byte[responseLength];
        await ReadExactlyAsync(stream, response, cancellationToken);

        return response;
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken);
            if (read == 0)
                throw new EndOfStreamException("Unexpected end of stream.");
            offset += read;
        }
    }

    private static bool IsTruncated(byte[] response)
    {
        if (response.Length < 4)
            throw new InvalidDataException("DNS response too short.");

        var flags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2));
        return (flags & 0x0200) != 0; // TC bit
    }

    private static DnsQueryPacket BuildQuery(string fqdn)
    {
        var buffer = new ArrayBufferWriter<byte>(512);

        Span<byte> header = stackalloc byte[12];
        var id = RandomNumberGenerator.GetHexString(4);
        var messageId = Convert.ToUInt16(id, 16);

        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], messageId);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], 0x0100); // RD
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1);      // QDCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], 0);      // ANCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(header[8..10], 0);     // NSCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(header[10..12], 0);    // ARCOUNT

        buffer.Write(header);

        WriteQName(buffer, fqdn);

        Span<byte> questionFooter = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(questionFooter[0..2], SRV);
        BinaryPrimitives.WriteUInt16BigEndian(questionFooter[2..4], 1); // IN
        buffer.Write(questionFooter);

        return new DnsQueryPacket(messageId, buffer.WrittenMemory);
    }

    private static void WriteQName(IBufferWriter<byte> buffer, string fqdn)
    {
        foreach (var label in fqdn.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);
            if (labelBytes.Length is 0 or > 63)
                throw new ArgumentException($"Invalid DNS label '{label}'.", nameof(fqdn));

            buffer.Write(new[] { (byte)labelBytes.Length });
            buffer.Write(labelBytes);
        }

        buffer.Write([0]);
    }

    private static IReadOnlyList<SrvRecord> ParseSrvResponse(byte[] message, ushort expectedId)
    {
        if (message.Length < 12)
            throw new InvalidDataException("DNS response too short.");

        var reader = new DnsMessageReader(message);

        var id = reader.ReadUInt16();
        if (id != expectedId)
            throw new InvalidDataException("DNS response ID mismatch.");

        var flags = reader.ReadUInt16();
        var qdCount = reader.ReadUInt16();
        var anCount = reader.ReadUInt16();
        var nsCount = reader.ReadUInt16();
        var arCount = reader.ReadUInt16();

        var isResponse = (flags & 0x8000) != 0;
        if (!isResponse)
            throw new InvalidDataException("Not a DNS response.");

        var rcode = flags & 0x000F;
        if (rcode != 0)
            throw new DnsQueryException($"DNS server returned error code {rcode}.", rcode);

        for (var i = 0; i < qdCount; i++)
        {
            _ = reader.ReadName();
            _ = reader.ReadUInt16(); // qtype
            _ = reader.ReadUInt16(); // qclass
        }

        var results = new List<SrvRecord>();

        for (var i = 0; i < anCount; i++)
        {
            _ = reader.ReadName(); // name
            var type = reader.ReadUInt16();
            var @class = reader.ReadUInt16();
            _ = reader.ReadUInt32(); // ttl
            var rdLength = reader.ReadUInt16();

            var rdataStart = reader.Position;

            if (type == SRV && @class == 1)
            {
                var priority = reader.ReadUInt16();
                var weight = reader.ReadUInt16();
                var port = reader.ReadUInt16();
                var target = reader.ReadName();

                results.Add(new SrvRecord(Target: target.TrimEnd('.'), Port: port, Priority: priority, Weight: weight));
            }

            reader.Position = rdataStart + rdLength;
            if (reader.Position > message.Length)
                throw new InvalidDataException("RDATA exceeds message length.");
        }

        SkipResourceRecords(reader, nsCount);
        SkipResourceRecords(reader, arCount);

        return results.OrderBy(r => r.Priority).ThenByDescending(r => r.Weight).ToArray();
    }

    private static void SkipResourceRecords(DnsMessageReader reader, int count)
    {
        for (var i = 0; i < count; i++)
        {
            _ = reader.ReadName();
            _ = reader.ReadUInt16();
            _ = reader.ReadUInt16();
            _ = reader.ReadUInt32();
            var rdLength = reader.ReadUInt16();
            reader.Position += rdLength;

            if (reader.Position > reader.Length)
                throw new InvalidDataException("DNS record exceeds message length.");
        }
    }

    private readonly record struct DnsQueryPacket(ushort Id, ReadOnlyMemory<byte> Buffer);
}

public sealed record SrvRecord(string Target, int Port, int Priority, int Weight);

public sealed class DnsQueryException(string message, int responseCode) : Exception(message)
{
    public int ResponseCode { get; } = responseCode;
}

internal sealed class DnsMessageReader(byte[] buffer)
{
    public int Position { get; set; }
    public int Length => buffer.Length;

    public ushort ReadUInt16()
    {
        EnsureAvailable(2);
        var value = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(Position, 2));
        Position += 2;
        return value;
    }

    public uint ReadUInt32()
    {
        EnsureAvailable(4);
        var value = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(Position, 4));
        Position += 4;
        return value;
    }

    public string ReadName()
    {
        var originalPosition = Position;
        var jumped = false;
        var jumpCount = 0;
        var labels = new List<string>();

        while (true)
        {
            EnsureAvailableAt(Position, 1);
            var length = buffer[Position];

            if ((length & 0xC0) == 0xC0)
            {
                EnsureAvailableAt(Position, 2);
                var pointer = ((length & 0x3F) << 8) | buffer[Position + 1];

                if (!jumped)
                {
                    originalPosition = Position + 2;
                }

                Position = pointer;
                jumped = true;

                jumpCount++;
                if (jumpCount > 16)
                    throw new InvalidDataException("Too many DNS compression jumps.");

                continue;
            }

            Position++;

            if (length == 0)
                break;

            EnsureAvailableAt(Position, length);
            var label = Encoding.ASCII.GetString(buffer, Position, length);
            labels.Add(label);
            Position += length;
        }

        if (jumped)
        {
            Position = originalPosition;
        }

        return string.Join('.', labels);
    }

    private void EnsureAvailable(int count) => EnsureAvailableAt(Position, count);

    private void EnsureAvailableAt(int position, int count)
    {
        if (position < 0 || position + count > buffer.Length)
            throw new InvalidDataException("Unexpected end of DNS message.");
    }
}

internal static class BufferWriterExtensions
{
    public static void Write(this IBufferWriter<byte> writer, ReadOnlySpan<byte> source)
    {
        var span = writer.GetSpan(source.Length);
        source.CopyTo(span);
        writer.Advance(source.Length);
    }
}