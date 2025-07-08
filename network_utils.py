import psutil

def get_network_info():
    """ Fetches network interfaces and their addresses. """
    return psutil.net_if_addrs()  # Return only the network addresses
