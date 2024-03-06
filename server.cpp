#include <iostream>

#include <cstdlib>
#include <cerrno>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <systemd/sd-daemon.h>

#define TOK_LISTEN "listen"
#define TOK_ACCEPT "accept"

void get_sock_opt(int fd, int level, int opt_name, void *data, socklen_t opt_len)
{
    socklen_t opt_len_out = opt_len;
    int res = getsockopt(fd, level, opt_name, data, &opt_len_out);
    if (res != 0)
    {
        throw std::string(strerror(errno));
    }
    if (opt_len != opt_len_out)
    {
        std::cout << "Warning: output size " << opt_len_out
                  << " different than provided size " << opt_len
                  << " for level " << level
                  << " option " << opt_name
                  << std::endl;
    }
}

int get_sock_opt_int(int fd, int level, int opt_name)
{
    int tmp;
    get_sock_opt(fd, level, opt_name, &tmp, sizeof(tmp));
    return tmp;
}

std::string get_so_type_str(int fd)
{
    int so_type = get_sock_opt_int(fd, SOL_SOCKET, SO_TYPE);
    std::string so_type_str;
    switch (so_type & 0xFF) // remove flags
    {
    case SOCK_STREAM:
        so_type_str = "SOCK_STREAM";
        break;
    case SOCK_DGRAM:
        so_type_str = "SOCK_DGRAM";
        break;
    case SOCK_RAW:
        so_type_str = "SOCK_RAW";
        break;
    case SOCK_RDM:
        so_type_str = "SOCK_RDM";
        break;
    case SOCK_SEQPACKET:
        so_type_str = "SOCK_SEQPACKET";
        break;
    case SOCK_DCCP:
        so_type_str = "SOCK_DCCP";
        break;
    case SOCK_PACKET:
        so_type_str = "SOCK_PACKET";
        break;
    default:
        so_type_str = "Unknown" + std::to_string(so_type);
        break;
    }
    if ((so_type & SOCK_CLOEXEC) == SOCK_CLOEXEC)
    {
        so_type_str += "+SOCK_CLOEXEC";
    }
    if ((so_type & SOCK_NONBLOCK) == SOCK_NONBLOCK)
    {
        so_type_str += "+SOCK_NONBLOCK";
    }
    return so_type_str;
}

std::string get_so_domain_str(int fd)
{
    int so_domain = get_sock_opt_int(fd, SOL_SOCKET, SO_DOMAIN);
    switch (so_domain)
    {
    case AF_UNIX:
        return "AF_UNIX";
    case AF_INET:
        return "AF_INET";
    case AF_AX25:
        return "AF_AX25";
    case AF_IPX:
        return "AF_IPX";
    case AF_APPLETALK:
        return "AF_APPLETALK";
    case AF_X25:
        return "AF_X25";
    case AF_INET6:
        return "AF_INET6";
    case AF_DECnet:
        return "AF_DECnet";
    case AF_KEY:
        return "AF_KEY";
    case AF_NETLINK:
        return "AF_NETLINK";
    case AF_PACKET:
        return "AF_PACKET";
    case AF_RDS:
        return "AF_RDS";
    case AF_PPPOX:
        return "AF_PPPOX";
    case AF_LLC:
        return "AF_LLC";
    case AF_IB:
        return "AF_IB";
    case AF_MPLS:
        return "AF_MPLS";
    case AF_CAN:
        return "AF_CAN";
    case AF_TIPC:
        return "AF_TIPC";
    case AF_BLUETOOTH:
        return "AF_BLUETOOTH";
    case AF_ALG:
        return "AF_ALG";
    case AF_VSOCK:
        return "AF_VSOCK";
    case AF_KCM:
        return "AF_KCM";
    case AF_XDP:
        return "AF_XDP";
    default:
        return "Unknown " + std::to_string(so_domain);
    }
}

std::string get_so_protocol_str(int fd)
{
    int so_protocol = get_sock_opt_int(fd, SOL_SOCKET, SO_PROTOCOL);
    switch (so_protocol)
    {
    case IPPROTO_IP:
        return "IPPROTO_IP";
    case IPPROTO_ICMP:
        return "IPPROTO_ICMP";
    case IPPROTO_IGMP:
        return "IPPROTO_IGMP";
    case IPPROTO_IPIP:
        return "IPPROTO_IPIP";
    case IPPROTO_TCP:
        return "IPPROTO_TCP";
    case IPPROTO_EGP:
        return "IPPROTO_EGP";
    case IPPROTO_PUP:
        return "IPPROTO_PUP";
    case IPPROTO_UDP:
        return "IPPROTO_UDP";
    case IPPROTO_IDP:
        return "IPPROTO_IDP";
    case IPPROTO_TP:
        return "IPPROTO_TP";
    case IPPROTO_DCCP:
        return "IPPROTO_DCCP";
    case IPPROTO_IPV6:
        return "IPPROTO_IPV6";
    case IPPROTO_RSVP:
        return "IPPROTO_RSVP";
    case IPPROTO_GRE:
        return "IPPROTO_GRE";
    case IPPROTO_ESP:
        return "IPPROTO_ESP";
    case IPPROTO_AH:
        return "IPPROTO_AH";
    case IPPROTO_MTP:
        return "IPPROTO_MTP";
    case IPPROTO_BEETPH:
        return "IPPROTO_BEETPH";
    case IPPROTO_ENCAP:
        return "IPPROTO_ENCAP";
    case IPPROTO_PIM:
        return "IPPROTO_PIM";
    case IPPROTO_COMP:
        return "IPPROTO_COMP";
    case IPPROTO_SCTP:
        return "IPPROTO_SCTP";
    case IPPROTO_UDPLITE:
        return "IPPROTO_UDPLITE";
    case IPPROTO_MPLS:
        return "IPPROTO_MPLS";
    case IPPROTO_RAW:
        return "IPPROTO_RAW";
    default:
        return "Unknown" + std::to_string(so_protocol);
    }
}

void display_fd_info(int fd)
{
    std::cout << "  Socket domain: " << get_so_domain_str(fd) << std::endl;
    std::cout << "  Socket protocol: " << get_so_protocol_str(fd) << std::endl;
    std::cout << "  Socket type: " << get_so_type_str(fd) << std::endl;

    // settings
    std::cout << "  Socket listening: " << get_sock_opt_int(fd, SOL_SOCKET, SO_ACCEPTCONN) << std::endl;
    std::cout << "  Socket keepalive: " << get_sock_opt_int(fd, SOL_SOCKET, SO_KEEPALIVE) << std::endl;
    std::cout << "  Socket mark: " << get_sock_opt_int(fd, SOL_SOCKET, SO_MARK) << std::endl;
    std::cout << "  Socket reuse address: " << get_sock_opt_int(fd, SOL_SOCKET, SO_REUSEADDR) << std::endl;
    std::cout << "  Socket reuse port: " << get_sock_opt_int(fd, SOL_SOCKET, SO_REUSEPORT) << std::endl;
    struct
    {
        int l_onoff;  /* linger active */
        int l_linger; /* how many seconds to linger for */
    } linger;
    get_sock_opt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
    std::cout << "  Socket linger: " << linger.l_onoff << " with seconds " << linger.l_linger << std::endl;
}

int run(std::string mode, std::string in_fifo)
{
    int val_int;

    if (mode != TOK_LISTEN && mode != TOK_ACCEPT)
    {
        std::cout << "Invalid systemd mode : only '" << TOK_LISTEN
                  << "' or '" << TOK_ACCEPT
                  << "' are accepted"
                  << std::endl;
        return 1;
    }

    int n = sd_listen_fds(0);
    std::cout << "Number of file descriptors received: " << n << std::endl;
    for (int fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++)
    {
        std::cout << " File descriptor number: " << fd << std::endl;
        display_fd_info(fd);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cout << "Usage: " << argv[0] << " systmed_mode in_fifo_path" << std::endl;
        std::cout << "- systemd_mode = '" TOK_LISTEN "' or '" TOK_ACCEPT "'" << std::endl;
        std::cout << "- in_fifo_cmd = fifo name where commands will be read" << std::endl;
        exit(1);
    }

    try
    {
        run(argv[1], argv[2]);
        return 0;
    }
    catch (std::string msg)
    {
        std::cout << "Exception: " << msg << std::endl;
        return 2;
    }
    catch (...)
    {
        std::cout << "Exception inconnue." << std::endl;
        return 2;
    }
}
