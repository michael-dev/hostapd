#ifdef CONFIG_MACVLAN
int macvlan_add_interface(const int ifidx, const char* ifname, char* mode, u8* macaddr);
int macvlan_del_interface(const int ifidx);
int macvlan_interface_change_mac(const int ifidx, int add, const u8* macaddr);
#endif /* CONFIG_MACVLAN */
