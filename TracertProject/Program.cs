using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;

class MyTracert
{
    // Константы для ICMP-сообщений
    const byte ICMP_ECHO_REQUEST = 8;    // Эхо-запрос
    const byte ICMP_ECHO_REPLY = 0;    // Эхо-ответ
    const byte ICMP_TIME_EXCEEDED = 11;   // Превышено время жизни пакета
    const int ICMP_HEADER_SIZE = 8;    // Размер заголовка ICMP в байтах

    // Вычисляет контрольную сумму по алгоритму RFC1071.
    static ushort ComputeChecksum(byte[] data)
    {
        uint sum = 0;
        int i = 0;
        while (i < data.Length - 1)
        {
            ushort word = (ushort)((data[i] << 8) + data[i + 1]);
            sum += word;
            i += 2;
        }
        if (i < data.Length)
        {
            sum += (uint)(data[i] << 8);
        }
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (ushort)(~sum);
    }

    // Создает ICMP Echo запрос с заданными идентификатором и номером последовательности.
    static byte[] CreateIcmpPacket(ushort id, ushort seq)
    {
        byte[] packet = new byte[ICMP_HEADER_SIZE];
        packet[0] = ICMP_ECHO_REQUEST; // Тип запроса: эхо (8)
        packet[1] = 0;                 // Код равен 0
        packet[2] = 0;                 // Контрольная сумма временно 0
        packet[3] = 0;

        // Идентификатор (2 байта)
        packet[4] = (byte)(id >> 8);
        packet[5] = (byte)(id & 0xFF);
        // Номер последовательности (2 байта)
        packet[6] = (byte)(seq >> 8);
        packet[7] = (byte)(seq & 0xFF);

        // Вычисляем и записываем контрольную сумму
        ushort checksum = ComputeChecksum(packet);
        packet[2] = (byte)(checksum >> 8);
        packet[3] = (byte)(checksum & 0xFF);
        return packet;
    }

    // Проверяет, что полученный пакет является корректным ответом на исходный запрос.
    // При этом вычисляется реальная длина внешнего IP-заголовка (из IHL),
    // а для ICMP TIME_EXCEEDED извлекается внутренний (исходный) IP-заголовок с его длиной.
    static bool IsValidResponse(byte[] buffer, int received, ushort id, ushort seq)
    {
        if (received < 1)
            return false;

        // IP-заголовок начинается с первого байта: младшие 4 бита дают IHL (в словах по 4 байта)
        int ipHeaderLength = (buffer[0] & 0x0F) * 4;
        if (received < ipHeaderLength + ICMP_HEADER_SIZE)
            return false;

        // Тип ICMP-сообщения находится сразу после внешнего IP-заголовка
        byte type = buffer[ipHeaderLength];

        if (type == ICMP_ECHO_REPLY)
        {
            // Проверяем поля для эхо-ответа
            if (received < ipHeaderLength + ICMP_HEADER_SIZE)
                return false;
            ushort replyId = (ushort)((buffer[ipHeaderLength + 4] << 8) | buffer[ipHeaderLength + 5]);
            ushort replySeq = (ushort)((buffer[ipHeaderLength + 6] << 8) | buffer[ipHeaderLength + 7]);
            return (replyId == id && replySeq == seq);
        }
        else if (type == ICMP_TIME_EXCEEDED)
        {
            // В сообщении ICMP TIME_EXCEEDED содержится копия начального пакета:
            // [Внешний IP-заголовок] + [8 байт ICMP заголовка] +
            // [Внутренний (оригинальный) IP-заголовок] + [первые 8 байт исходного ICMP запроса].
            int minExpected = ipHeaderLength + 8 + 20 + 8; // 20 – минимальная длина IP-заголовка без опций
            if (received < minExpected)
                return false;
            int innerIpHeaderStart = ipHeaderLength + 8;
            int innerIpHeaderLength = (buffer[innerIpHeaderStart] & 0x0F) * 4;
            if (received < innerIpHeaderStart + innerIpHeaderLength + 8)
                return false;
            int originalIcmpStart = innerIpHeaderStart + innerIpHeaderLength;
            ushort originalId = (ushort)((buffer[originalIcmpStart + 4] << 8) | buffer[originalIcmpStart + 5]);
            ushort originalSeq = (ushort)((buffer[originalIcmpStart + 6] << 8) | buffer[originalIcmpStart + 7]);
            return (originalId == id && originalSeq == seq);
        }
        return false;
    }

    // Выполняет трассировку маршрута до destination.
    // Для каждого значения TTL отправляются probesPerHop ICMP Echo запросов
    // и выводятся время отклика и IP-адреса маршрутизаторов.
    public static void DoTraceroute(string destination, int maxHops = 30, int timeout = 3000, int probesPerHop = 3)
    {
        IPAddress destAddr;
        try
        {
            destAddr = Dns.GetHostAddresses(destination)[0];
        }
        catch
        {
            Console.WriteLine($"Не удалось разрешить адрес: {destination}");
            return;
        }

        Console.WriteLine($"Трассировка маршрута к {destination} [{destAddr}]");
        Console.WriteLine($"с максимальным числом прыжков {maxHops}:\n");
     

        ushort identifier = (ushort)Process.GetCurrentProcess().Id;
        bool reachedDestination = false;

        for (int ttl = 1; ttl <= maxHops && !reachedDestination; ttl++)
        {
            Console.Write($"{ttl,2}  ");

            List<long?> rtts = new List<long?>();
            List<IPAddress> responders = new List<IPAddress>();

            for (int probe = 0; probe < probesPerHop; probe++)
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp))
                {
                    try
                    {
                        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, ttl);
                        socket.ReceiveTimeout = timeout;

                        IPEndPoint remoteEndpoint = new IPEndPoint(destAddr, 0);
                        EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);

                        ushort seq = (ushort)(ttl * probesPerHop + probe);
                        byte[] packet = CreateIcmpPacket(identifier, seq);

                        Stopwatch stopwatch = Stopwatch.StartNew();
                        socket.SendTo(packet, remoteEndpoint);
                        byte[] buffer = new byte[1500];
                        int received = socket.ReceiveFrom(buffer, ref remoteEP);
                        stopwatch.Stop();

                        if (IsValidResponse(buffer, received, identifier, seq))
                        {
                            IPAddress responder = ((IPEndPoint)remoteEP).Address;
                            rtts.Add(stopwatch.ElapsedMilliseconds);
                            responders.Add(responder);
                            if (responder.Equals(destAddr))
                            {
                                reachedDestination = true;
                            }
                        }
                        else
                        {
                            rtts.Add(null);
                        }
                    }
                    catch (SocketException)
                    {
                        rtts.Add(null);
                    }
                }
            }

            // Форматируем время для каждой пробы
            string time1 = rtts[0].HasValue ? $"{rtts[0],4} мс" : "    *";
            string time2 = rtts[1].HasValue ? $"{rtts[1],4} мс" : "    *";
            string time3 = rtts[2].HasValue ? $"{rtts[2],4} мс" : "    *";

            // Формируем строку с уникальными IP-адресами маршрутизаторов для данного TTL
            string routerIp = "";
            var distinctResponders = responders.Distinct().ToList();
            if (distinctResponders.Count > 0)
            {
                List<string> routerInfos = new List<string>();
                foreach (var ip in distinctResponders)
                {
                    string info = ip.ToString();
                    try
                    {
                        var hostEntry = Dns.GetHostEntry(ip);
                        if (!hostEntry.HostName.Equals(ip.ToString()))
                        {
                            info = $"{hostEntry.HostName} [{ip}]";
                        }
                    }
                    catch { }
                    routerInfos.Add(info);
                }
                routerIp = string.Join(" ", routerInfos);
            }
            else
            {
                routerIp = "*";
            }

            Console.WriteLine($"{time1}  {time2}  {time3}    {routerIp}");
        }
        Console.WriteLine("\nТрассировка завершена.");
    }

    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Использование: MyTracert.exe <IP-адрес или доменное имя>");
            return;
        }
        try
        {
            DoTraceroute(args[0]);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка: {ex.Message}");
        }
    }
}
