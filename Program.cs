using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Threading;
using System.Net;
using System.Text.RegularExpressions;

namespace Socks5_Proxy
{
    class Program
    {
        //client connection to be passed to a worker thread
        static TcpClient new_client = new TcpClient();
        //indicates weather a thread has started or not
        static Boolean start_state = false;
        //running threads are stored here
        static List<Thread> threads = new List<Thread>();

        //port to listen for connections on
        static int port = 1080;

        //host_deny_filter is a regex value that will cause a conenction to be declined when
        //matched against a given domain name. by default example.com is banned as an example
        static Regex host_deny_filter = new Regex(@"^(www\.)?example.com:80$", RegexOptions.IgnoreCase);

        //host_allow_filter is a regex value that overrides the host_deny filter. domains
        //matching this value will be allowed regardless of the host_deny_filter.
        static Regex host_allow_filter = new Regex(@"^example.com:80$", RegexOptions.IgnoreCase);

        //client_filter is a regex value that must match a clients IP address in order to use this server
        //the default value allows IPs 127.0.0.0 - 127.0.0.255. the following vlaue would allow any IP:
        //   ^(.*)$
        static Regex client_filter = new Regex(@"^127\.0\.0\.[0-9][0-9]?[0-9]?$", RegexOptions.IgnoreCase);

        static void Main(string[] args)
        {
            Console.WriteLine(Properties.Resources.welcome);
            try
            {
                Reset_Listener();
            } catch(Exception e)
            {
                Console.WriteLine("FATAL ERROR: " + e.Message);
                string f = Console.ReadLine();
            }
           
        }

        static void Reset_Listener()
        {
            TcpListener sock = new TcpListener(IPAddress.Any, port);
            while (true)
            {
                sock.Start();
                start_state = false;
                new_client = sock.AcceptTcpClient();


                while (threads.Count() > 99)
                {
                    //if we have 100 socket threads running then do a simple sleep loop
                    //until some theads close, then we continue accpeting connections
                    Log("Maximum threads running, waiting for threads to terminate...");
                    Thread.Sleep(1000);
                }

                //lets see if new_client is using an authorized ip address by matching it against the client_filter value
                string userIP = new_client.Client.RemoteEndPoint.ToString().Split(':')[0];
                if (client_filter.Match(userIP).Success)
                {
                    //they're not allowed! 

                    Log("New connection request from " + new_client.Client.RemoteEndPoint.ToString());
                    //We will make a new thread for this connection and
                    //Add the new thread to the list of threads
                    Thread worker = new Thread(new ThreadStart(Socket_Worker));
                    threads.Add(worker);
                    //Now we start the thread and wait for it to change
                    //the state of start_state to true to avoid cross
                    //threadding issues.
                    worker.Start();

                    while (start_state == false)
                    {
                        //Add a little snoozing to keep CPU usage down
                        Thread.Sleep(100);
                    }
                }
                else
                {
                    //they're not allowed!
                    Log("Attempted connection from an unauthorized ip " + userIP);
                    new_client.Close();
                }
                

            }
        }

        static void Socket_Worker()
        {
            //new_client is set to the current working TcpClient and the
            //main TcpListener is waiting for us to grab it, so we make a new
            //instance of the working TcpClient here. 
            TcpClient local = new TcpClient();
            local = new_client;

            //Now that we've grabbed our own instance of the TcpClient we
            //can tell the listener to continue via the boolean stat_state
            start_state = true;

            

            //1024 bytes should be more than enough for the socks5 handshake
            Byte[] socks_data = new Byte[1024];

            int address_type = 0;
            string remote_address = "";
            int remote_port = 0;
            Byte[] port_bytes = new byte[2];
            Byte[] address_bytes = new byte[1];
            try
            {
                Log("Accepted connection from " + local.Client.RemoteEndPoint.ToString());
                NetworkStream local_stream = new_client.GetStream();

                
                local_stream.Read(socks_data, 0, 2);
                //the client has sent us 2 bytes: the socks version and the
                //number of authentication methods to read
                if (socks_data[0] != 5 || socks_data[1] == 0)
                {
                    //if byte[0] ain't 5 then it ain't socks5
                    //if byte[1] is 0 then they didn't send use any methods.
                    throw new Exception("Socks handsake error 1");
                }
                else
                {
                    //everything checks out so lets make a buffer
                    //to read all the methods supported
                    byte[] socks_methods = new Byte[socks_data[1]];
                    local_stream.Read(socks_methods, 0, socks_data[1]);

                    //now lets loop through all methods to look for method 0
                    Boolean method_found = false;
                    
                    foreach(int method in socks_methods)
                    {
                        if (method == 0) method_found = true;
                    }
                    if (method_found)
                    {
                        //the "no authentication" method was found so let's select that
                        local_stream.Write(new Byte[] { 5, 0 }, 0, 2);

                        //now that we sleected no authentication we should get a connection request
                        local_stream.Read(socks_data, 0, 4);

                        if(socks_data[0]==5 && socks_data[1] == 1)
                        {
                            //byte[0] should be 5 for socks version 5
                            //byte[1] should be the command (1 for new TCP connection)
                            //byte[2] is unused
                            //byte[3] is the address type (1=ipv4, 2=??, 3=domain, 4=ipv6)
                            address_type = socks_data[3];
                            switch (socks_data[3])
                            {
                                case 1:
                                    //IPv4 ADDRESS
                                    //we need to read 4 bytes for the ip address
                                    address_bytes = new byte[4];
                                    local_stream.Read(address_bytes, 0, 4);
                                    //now lets build an address from the bytes
                                    remote_address = address_bytes[0] + "." + address_bytes[1] + "." + address_bytes[2] + "." + address_bytes[3];
                                    
                                    break;

                                case 3:
                                    //DOMAIN NAME ADDRESS
                                    //we need to get 1 byte for the length of domain bytes
                                    //then read all the domain bytes.
                                    local_stream.Read(socks_data, 0, 1);
                                    address_bytes = new byte[socks_data[0]];
                                    local_stream.Read(address_bytes, 0, socks_data[0]);

                                    //now we convert to bytes to ASCII
                                    remote_address = ASCIIEncoding.ASCII.GetString(address_bytes);
                                    break;

                                case 4:
                                    throw new Exception("NO IPv6");

                                default:
                                    throw new Exception("Socks handsake error 2");
                            }

                            //now we read the port bytes
                            local_stream.Read(port_bytes, 0, 2);
                            //now lets convert it to an integer
                            remote_port = BitConverter.ToInt16(new byte[] { port_bytes[1], port_bytes[0] }, 0);

                            //lets verify the requested host is allowed
                            if (host_deny_filter.Match(remote_address + ":" + remote_port).Success && !host_allow_filter.Match(remote_address + ":" + remote_port).Success)
                            {
                                //the domin is not allowed
                                if (address_type == 1) local_stream.Write(new Byte[] { 5, 2, 0, 1 }, 0, 4);

                                local_stream.Write(address_bytes, 0, address_bytes.Count());

                                local_stream.Write(port_bytes, 0, 2);

                                throw new Exception("Connection to banned address " + local.Client.RemoteEndPoint.ToString() + " to " + remote_address);
                            }
                            else
                            {
                                //domain is allowed
                                //now we attempt to make a connection to the requested address
                                try
                                {

                                    TcpClient remote_client = new TcpClient(remote_address, remote_port);
                                    NetworkStream remote_stream = remote_client.GetStream();
                                    //success! lets end the socks handshake and pass on the connection
                                    if (address_type == 1) local_stream.Write(new Byte[] { 5, 0, 0, 1 }, 0, 4);

                                    if (address_type == 3) local_stream.Write(new Byte[] { 5, 0, 0, 3, (byte)address_bytes.Count() }, 0, 5);

                                    local_stream.Write(address_bytes, 0, address_bytes.Count());

                                    local_stream.Write(port_bytes, 0, 2);

                                    Log("Connection Success from " + local.Client.RemoteEndPoint.ToString() + " to " + remote_address);

                                    //now we call the data worker method.
                                    Data_Worker(local, remote_client, local_stream, remote_stream);
                                    remote_client.Close();
                                }
                                catch (Exception e)
                                {
                                    if (address_type == 1) local_stream.Write(new Byte[] { 5, 4, 0, 1 }, 0, 4);

                                    local_stream.Write(address_bytes, 0, address_bytes.Count());

                                    local_stream.Write(port_bytes, 0, 2);
                                    Log("Connection Fail from " + local.Client.RemoteEndPoint.ToString() + " to " + remote_address);

                                }
                            }


                        }
                        else
                        {
                            throw new Exception("Socks handsake error 3");
                        }
                    }
                    else
                    {
                        //didn't find our method of "no authentication"
                        local_stream.Write(new Byte[] { 5, 255 }, 0, 2);
                        throw new Exception("No supported authentication methods found");
                    }
                    
                }

                

            }
            catch (Exception e)
            {
                Log("Error " + e.Message);
            }

            Log("Closing Connection ");
            local.Close();
            threads.Remove(Thread.CurrentThread);
        }

        static void Data_Worker(TcpClient local_client, TcpClient remote_client, NetworkStream local, NetworkStream remote)
        {
            //this method sends data back and forth between remote and local connections

            //set both clients to NoDelay, otherwise we'll be stuck waiting for data from one client while the other wants to send
            local_client.NoDelay = true;
            remote_client.NoDelay = true;

            //amount of miliseconds to limit data by
            int throttle = 5;

            //amount of time no data has been transferred
            int idle_count = 0;
            //amount of bytes thats have been transferred in total.
            int byte_count = 0;

            while(local_client.Connected && remote_client.Connected)
            {
                
                //we'll try to read 1 KiB of data each time
                Byte[] data = new byte[1024];
                //this will be the amount of data we /actually/ read
                int data_read = 0;


                if (local.DataAvailable)
                {

                    data_read = local.Read(data, 0, data.Count());
                    remote.Write(data, 0, data_read);
                    //since there was data to send we can reset the idle counter
                    idle_count = 0;
                    //increment the byte_count by the amount of bytes read
                    byte_count += data_read;
                }
                else if(remote.DataAvailable)
                {
                    data_read = remote.Read(data, 0, data.Count());
                    local.Write(data, 0, data_read);
                    //since there was data to send we can reset the idle counter
                    idle_count = 0;
                    //increment the byte_count by the amount of bytes read
                    byte_count += data_read;
                }
                else
                {
                    //after idle time has reached 100 (roughly 10 seconds) we close the socket
                    if (idle_count > 100) break;
                    idle_count++;
                    //sleep for 100 miliseconds minues the throttle speed
                    Thread.Sleep(100-throttle);
                }
                //throttle speed of data 
                Thread.Sleep(throttle);
            }
        }

        static void Log(String text)
        {
            //fo logging we just write to console. Do something more advanced here if you want
            Console.WriteLine(text);

        }
        

    }
}
