#if defined(WIN32) || defined(_WIN32)

#include <Winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include <tchar.h>

#include "../../lft_ifname.h"

typedef enum {
    KWV_UNKNOWN,    //while unknown (before first call of this module)
	KWV_VISTA,		//Vista
    KWV_2K,         //98/ME, NTSP4, W2K and XP
    KWV_NT4,        //NT4 with SP<4
    KWV_95          //Win95
}KNOWN_WIN_VERSION;

static KNOWN_WIN_VERSION VerifyWindowsVersion()
{
    static KNOWN_WIN_VERSION WinVersion=KWV_UNKNOWN;
    OSVERSIONINFOEX osvi;
    BOOL bOsVersionInfoEx;

    if(WinVersion!=KWV_UNKNOWN)
        return WinVersion;

    // Try calling GetVersionEx using the OSVERSIONINFOEX structure.
    // If that fails, try using the OSVERSIONINFO structure.

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if(!(bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO *) &osvi)))
    {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if(!GetVersionEx( (OSVERSIONINFO *) &osvi)) 
            return KWV_UNKNOWN;
    }
    switch(osvi.dwPlatformId)
    {
    case VER_PLATFORM_WIN32_NT:         //Test for the Windows NT product family
         if(osvi.dwMajorVersion<=4)     //NT4
         {
             if(osvi.wServicePackMajor<4)
                 WinVersion=KWV_NT4;
             else
                 WinVersion=KWV_2K;
         }
         else
		 {
			 if(osvi.dwMajorVersion>5)
				 WinVersion=KWV_VISTA;
			 else
				WinVersion=KWV_2K;         //2K and XP
		 }
         break;
    case VER_PLATFORM_WIN32_WINDOWS:    //Test for the Windows Me/98/95
    default:
        WinVersion=KWV_95;
        break;
    }
    return WinVersion;
}

static u_long lft_getifaddr_95(const char *argifname)
{
    HKEY key;
    char ethname[5]="eth/";
    char pppname[5]="ppp/";
    int i;
    FILETIME update;
    LONG res;
    DWORD size;
    u_long ret;
    char ifname[256];

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Enum\\Network\\MSTCP", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return -1;
    size = sizeof(ifname);
    for(i=0;(res = RegEnumKeyEx(key, i, (LPTSTR)ifname, &size, 0, 0, 0, &update))!=ERROR_NO_MORE_ITEMS;i++)
    {
        HKEY ifkey, subkey;
        DWORD dsize,ipsize,npsize,asize;
        char driver[256], classname[256], netname[256];
        char adapter[256], ip[256], np[256];

        if(res != ERROR_SUCCESS || RegOpenKeyEx(key, (LPCTSTR)ifname, 0, KEY_READ, &ifkey) != ERROR_SUCCESS)
            continue;

        dsize = sizeof(driver);
        if(RegQueryValueEx(ifkey, L"Driver", 0, NULL, (unsigned char *)driver, &dsize) != ERROR_SUCCESS)
        {
            RegCloseKey(ifkey);
            continue;
        }

        strcpy(classname, "System\\CurrentControlSet\\Services\\Class\\");
        strcat(classname, driver);
        if((res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)classname, 0, KEY_READ, &subkey)) != ERROR_SUCCESS)
        {
            RegCloseKey(ifkey);
            continue;
        }
        ipsize=sizeof(ip);
        npsize=sizeof(np);
        if(RegQueryValueEx(subkey, L"IPAddress", 0, NULL, (unsigned char *) ip, &ipsize) == ERROR_SUCCESS)
        {
            ret=inet_addr(ip);
            RegCloseKey (subkey);

            strcpy(netname, "System\\CurrentControlSet\\Services\\Class\\Net\\");
            strcat(netname, ifname);
            
            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)netname, 0, KEY_READ, &subkey) != ERROR_SUCCESS)
            {
                RegCloseKey(ifkey);
                continue;
            }
            
            asize=sizeof(adapter);
            if( RegQueryValueEx (subkey, L"AdapterName", 0, NULL, (unsigned char *) adapter, &asize) == ERROR_SUCCESS &&
                !strcmp(adapter, "MS$PPP"))
            {
                pppname[3]++;
            }
            else
            {
                ethname[3]++;
            }
            RegCloseKey(subkey);
            RegCloseKey(ifkey);
            if(!strcmp(pppname,argifname) || !strcmp(ethname,argifname))
                break;
            else
                ret=-1;
        }
    }
    RegCloseKey(key);
    return ret;
}

static char * lft_getifname_95(struct in_addr addr)
{
    HKEY key;
    char ethname[5]="eth/";
    char pppname[5]="ppp/";
    int i;
    FILETIME update;
    LONG res;
    DWORD size;
    u_long ret;
    int isethaddr,isfound;
    char ifname[256];

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Enum\\Network\\MSTCP", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return NULL;
    size = sizeof(ifname);
    for(i=0;(res = RegEnumKeyEx(key, i, (TCHAR *)ifname, &size, 0, 0, 0, &update))!=ERROR_NO_MORE_ITEMS;i++)
    {
        HKEY ifkey, subkey;
        DWORD dsize,ipsize,npsize,asize;
        char driver[256], classname[256], netname[256];
        char adapter[256], ip[256], np[256];

        if(res != ERROR_SUCCESS || RegOpenKeyEx(key, (LPCTSTR)ifname, 0, KEY_READ, &ifkey) != ERROR_SUCCESS)
            continue;

        dsize = sizeof(driver);
        if(RegQueryValueEx(ifkey, L"Driver", 0, NULL, (unsigned char *)driver, &dsize) != ERROR_SUCCESS)
        {
            RegCloseKey(ifkey);
            continue;
        }

        strcpy(classname, "System\\CurrentControlSet\\Services\\Class\\");
        strcat(classname, driver);
        if((res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)classname, 0, KEY_READ, &subkey)) != ERROR_SUCCESS)
        {
            RegCloseKey(ifkey);
            continue;
        }
        ipsize=sizeof(ip);
        npsize=sizeof(np);
        if(RegQueryValueEx(subkey, L"IPAddress", 0, NULL, (unsigned char *) ip, &ipsize) == ERROR_SUCCESS)
        {
            ret=inet_addr(ip);
            RegCloseKey (subkey);

            strcpy(netname, "System\\CurrentControlSet\\Services\\Class\\Net\\");
            strcat(netname, ifname);
            
            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)netname, 0, KEY_READ, &subkey) != ERROR_SUCCESS)
            {
                RegCloseKey(ifkey);
                continue;
            }
            
            asize=sizeof(adapter);
            if( RegQueryValueEx (subkey, L"AdapterName", 0, NULL, (unsigned char *) adapter, &asize) == ERROR_SUCCESS &&
                !strcmp(adapter, "MS$PPP"))
            {
                pppname[3]++;
                isethaddr=0;
            }
            else
            {
                ethname[3]++;
                isethaddr=1;
            }
            RegCloseKey(subkey);
            RegCloseKey(ifkey);
            if(ret==addr.s_addr)
            {
                isfound=1;
                break;
            }
            else
                isfound=0;
        }
    }
    RegCloseKey(key);
    if(!isfound)
        return NULL;
    if(isethaddr)
        return strdup(ethname);
    return strdup(pppname);
}

static u_long lft_getifaddr_NT4(const char *ifname)
{
    HKEY key;
    char devname[256];
    struct sockaddr_in *sa = NULL;
    struct sockaddr *so = NULL;
    DWORD size;
    int cnt = 1,isfound;
    u_long ret;
    char *binding = (char *)0;

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Linkage", 0, KEY_READ, &key) == ERROR_SUCCESS)
    {
        if(RegQueryValueEx(key, L"Bind", NULL, NULL, NULL, &size) == ERROR_SUCCESS)
        {
            binding = (char *)_alloca(size);
            if(RegQueryValueEx (key, L"Bind", NULL, NULL, (unsigned char *)binding, &size) != ERROR_SUCCESS)
                binding = NULL;
        }
        RegCloseKey(key);
    }

    if(binding)
    {
        char *bp, eth[2] = "/";
        int ipsize;
        char cardkey[256], ipaddress[256];

        for(bp = binding; *bp; bp+=strlen(bp)+1)
        {
            bp += strlen("\\Device\\");
            strcpy(cardkey, "SYSTEM\\CurrentControlSet\\Services\\");
            strcat(cardkey, bp);
            strcat(cardkey, "\\Parameters\\Tcpip");

            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)cardkey, 0, KEY_READ, &key) != ERROR_SUCCESS)
                continue;
            ipsize=256;
            if(RegQueryValueEx(key, L"IPAddress", NULL, NULL, (unsigned char *) ipaddress, &ipsize) == ERROR_SUCCESS)
            {
                char *ip;

                for(ip = ipaddress; *ip; ip += strlen(ip)+1)
                {
                    if(!strncmp(bp, "NdisWan", 7))
                    {
                        strcpy(devname, "ppp");
                        strcat(devname, bp + 7);
                    }
                    else
                    {
                        eth[0]++;
                        strcpy(devname, "eth");
                        strcat(devname, eth);
                    }
                    ret=inet_addr(ipaddress);
                    if(!ret)
                    {
                        ipsize=256;
                        if(RegQueryValueEx (key, L"DhcpIPAddress", NULL, NULL, (unsigned char *) ipaddress, &ipsize) == ERROR_SUCCESS)
                        {
                            ret=inet_addr(ipaddress);
                        }
                    }
                    if(!strcmp(devname,ifname))
                    {
                        isfound=1;
                        break;
                    }
                    else
                        isfound=0;
                }
            }
            RegCloseKey(key);
            if(isfound)
                return ret;
        }
    }
    return -1;
}

static char * lft_getifname_NT4(struct in_addr addr)
{
    HKEY key;
    char devname[256];
    struct sockaddr_in *sa = NULL;
    struct sockaddr *so = NULL;
    DWORD size;
    int cnt = 1,isfound;
    u_long ret;
    char *binding = (char *)0;

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Linkage", 0, KEY_READ, &key) == ERROR_SUCCESS)
    {
        if(RegQueryValueEx(key, L"Bind", NULL, NULL, NULL, &size) == ERROR_SUCCESS)
        {
            binding = (char *)_alloca(size);
            if(RegQueryValueEx (key, L"Bind", NULL, NULL, (unsigned char *)binding, &size) != ERROR_SUCCESS)
                binding = NULL;
        }
        RegCloseKey(key);
    }

    if(binding)
    {
        char *bp, eth[2] = "/";
        int ipsize;
        char cardkey[256];
        char ipaddress[256];

        for(bp = binding; *bp; bp+=strlen(bp)+1)
        {
            bp += strlen("\\Device\\");
            strcpy(cardkey, "SYSTEM\\CurrentControlSet\\Services\\");
            strcat(cardkey, bp);
            strcat(cardkey, "\\Parameters\\Tcpip");

            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)cardkey, 0, KEY_READ, &key) != ERROR_SUCCESS)
                continue;
            ipsize=256;
            if(RegQueryValueEx(key, L"IPAddress", NULL, NULL, (unsigned char *) ipaddress, &ipsize) == ERROR_SUCCESS)
            {
                char *ip;

                for(ip = ipaddress; *ip; ip += strlen(ip)+1)
                {
                    if(!strncmp(bp, "NdisWan", 7))
                    {
                        strcpy(devname, "ppp");
                        strcat(devname, bp + 7);
                    }
                    else
                    {
                        eth[0]++;
                        strcpy(devname, "eth");
                        strcat(devname, eth);
                    }
                    ret=inet_addr(ipaddress);
                    if(!ret)
                    {
                        ipsize=256;
                        if(RegQueryValueEx (key, L"DhcpIPAddress", NULL, NULL, (unsigned char *) ipaddress, &ipsize) == ERROR_SUCCESS)
                        {
                            ret=inet_addr(ipaddress);
                        }
                    }
                    if(addr.s_addr==ret)
                    {
                        isfound=1;
                        break;
                    }
                    else
                        isfound=0;
                }
            }
            RegCloseKey(key);
            if(isfound)
                return strdup(devname);
        }
    }
    return NULL;
}

static u_long lft_getifaddr_2K(const char *ifname)
{
  int cnt = 0;
  int ethId = 0, pppId = 0, slpId = 0, tokId = 0;
  DWORD ip_cnt;
  DWORD siz_ip_table = 0;
  PMIB_IPADDRTABLE ipt;
  PMIB_IFROW ifrow;
  char devname[256];

  typedef struct
  {
    DWORD ifIndex;
    size_t count;
    unsigned int enumerated;	// for eth0:1
    unsigned int classId;	// for eth0, tok0 ...

  } ifcount_t;
  ifcount_t *iflist, *ifEntry;

  if(GetIpAddrTable (NULL, &siz_ip_table, TRUE) == ERROR_INSUFFICIENT_BUFFER)
  {
      ifrow = (PMIB_IFROW)_alloca(sizeof(MIB_IFROW));
      ipt = (PMIB_IPADDRTABLE)_alloca(siz_ip_table);
  }
  if(GetIpAddrTable (ipt, &siz_ip_table, TRUE) != NO_ERROR)
      return -1;
  iflist = (ifcount_t *) alloca(sizeof(ifcount_t)*(ipt->dwNumEntries + 1));
  memset(iflist, 0, sizeof (ifcount_t) * (ipt->dwNumEntries + 1));
  for(ip_cnt = 0; ip_cnt < ipt->dwNumEntries; ++ip_cnt)
  {
      ifEntry = iflist;
	  /* search for matching entry (and stop at first free entry) */
	  while(ifEntry->count != 0)
      {
          if(ifEntry->ifIndex == ipt->table[ip_cnt].dwIndex)
              break;
          ifEntry++;
      }
	  if(ifEntry->count == 0)
      {
          ifEntry->count = 1;
          ifEntry->ifIndex = ipt->table[ip_cnt].dwIndex;
      }
      else
      {
          ifEntry->count++;
      }
  }
  // reset the last element. This is just the stopper for the loop.
  iflist[ipt->dwNumEntries].count = 0;
  for(ip_cnt = 0; ip_cnt < ipt->dwNumEntries; ip_cnt++)
  {
	  ifcount_t *ifEntry = iflist;
      memset(ifrow, 0, sizeof(MIB_IFROW));
	  ifrow->dwIndex = ipt->table[ip_cnt].dwIndex;
      if(GetIfEntry(ifrow) != NO_ERROR)
          continue;

	  /* search for matching entry (and stop at first free entry) */
	  while(ifEntry->count != 0)
      {
          if(ifEntry->ifIndex == ipt->table[ip_cnt].dwIndex)
              break;
          ifEntry++;
      }
	  /* Setup the interface name */
	  switch(ifrow->dwType)
      {
      case MIB_IF_TYPE_TOKENRING:
          if(ifEntry->enumerated == 0)
          {
              ifEntry->classId = tokId++;
              sprintf(devname, "tok%u", ifEntry->classId);
          }
          else
		  {
              sprintf(devname, "tok%u:%u", ifEntry->classId, ifEntry->enumerated - 1);
		  }
          ifEntry->enumerated++;
          break;
#ifdef IF_TYPE_IEEE80211
	  case IF_TYPE_IEEE80211:
#endif
      case MIB_IF_TYPE_ETHERNET:
          if(ifEntry->enumerated == 0)
		  {
              ifEntry->classId = ethId++;
              sprintf(devname, "eth%u", ifEntry->classId);
		  }
          else
		  {
              sprintf(devname, "eth%u:%u", ifEntry->classId, ifEntry->enumerated - 1);
		  }
          ifEntry->enumerated++;
          break;
      case MIB_IF_TYPE_PPP:
          if(ifEntry->enumerated == 0)
		  {
              ifEntry->classId = pppId++;
              sprintf(devname, "ppp%u", ifEntry->classId);
		  }
          else
		  {
              sprintf(devname, "ppp%u:%u", ifEntry->classId, ifEntry->enumerated - 1);
		  }
          ifEntry->enumerated++;
          break;
      case MIB_IF_TYPE_SLIP:
          if(ifEntry->enumerated == 0)
		  {
              ifEntry->classId = slpId++;
              sprintf(devname, "slp%u", ifEntry->classId);
		  }
          else
		  {
              sprintf(devname, "slp%u:%u", ifEntry->classId, ifEntry->enumerated - 1);
		  }
          ifEntry->enumerated++;
          break;
      case MIB_IF_TYPE_LOOPBACK:
          strcpy(devname, "lo");
          break;
      default:
          continue;
      }
      if(!strcmp(devname,ifname))
      {
          return ipt->table[ip_cnt].dwAddr;
      }
  }
  return -1;
}

static char * lft_getifname_2K(struct in_addr addr)
{
  int cnt = 0;
  int ethId = 0, pppId = 0, slpId = 0, tokId = 0;
  DWORD ip_cnt;
  DWORD siz_ip_table = 0;
  PMIB_IPADDRTABLE ipt;
  PMIB_IFROW ifrow;
  static char devname[256];
  static struct in_addr savedaddr;
  static int FirstTime=1;

  typedef struct
  {
    DWORD ifIndex;
    size_t count;
    unsigned int enumerated;	// for eth0:1
    unsigned int classId;	// for eth0, tok0 ...

  } ifcount_t;
  ifcount_t *iflist, *ifEntry;

  if(!FirstTime && savedaddr.s_addr==addr.s_addr)
  {
      return strdup(devname);
  }
  savedaddr.s_addr=addr.s_addr;
  if(GetIpAddrTable (NULL, &siz_ip_table, TRUE) == ERROR_INSUFFICIENT_BUFFER)
  {
      ifrow = (PMIB_IFROW)_alloca(sizeof(MIB_IFROW));
      ipt = (PMIB_IPADDRTABLE)_alloca(siz_ip_table);
  }
  if(GetIpAddrTable (ipt, &siz_ip_table, TRUE) != NO_ERROR)
      return NULL;
  iflist = (ifcount_t *) alloca(sizeof(ifcount_t)*(ipt->dwNumEntries + 1));
  memset(iflist, 0, sizeof (ifcount_t) * (ipt->dwNumEntries + 1));
  for(ip_cnt = 0; ip_cnt < ipt->dwNumEntries; ++ip_cnt)
  {
      ifEntry = iflist;
	  /* search for matching entry (and stop at first free entry) */
	  while(ifEntry->count != 0)
      {
          if(ifEntry->ifIndex == ipt->table[ip_cnt].dwIndex)
              break;
          ifEntry++;
      }
	  if(ifEntry->count == 0)
      {
          ifEntry->count = 1;
          ifEntry->ifIndex = ipt->table[ip_cnt].dwIndex;
      }
      else
      {
          ifEntry->count++;
      }
  }
  // reset the last element. This is just the stopper for the loop.
  iflist[ipt->dwNumEntries].count = 0;
  for(ip_cnt = 0; ip_cnt < ipt->dwNumEntries; ip_cnt++)
  {
	  ifcount_t *ifEntry = iflist;
      memset(ifrow, 0, sizeof(MIB_IFROW));
	  ifrow->dwIndex = ipt->table[ip_cnt].dwIndex;
      if(GetIfEntry(ifrow) != NO_ERROR)
          continue;

	  /* search for matching entry (and stop at first free entry) */
	  while(ifEntry->count != 0)
      {
          if(ifEntry->ifIndex == ipt->table[ip_cnt].dwIndex)
              break;
          ifEntry++;
      }
	  /* Setup the interface name */
	  switch(ifrow->dwType)
      {
      case MIB_IF_TYPE_TOKENRING:
          if(ifEntry->enumerated == 0)
          {
              ifEntry->classId = tokId++;
              sprintf(devname, "tok%u", ifEntry->classId);
          }
          else
		  {
              sprintf(devname, "tok%u:%u", ifEntry->classId, ifEntry->enumerated - 1);
		  }
          ifEntry->enumerated++;
          break;
#ifdef IF_TYPE_IEEE80211
	  case IF_TYPE_IEEE80211:
#endif
      case MIB_IF_TYPE_ETHERNET:
          if(ifEntry->enumerated == 0)
		  {
              ifEntry->classId = ethId++;
              sprintf(devname, "eth%u", ifEntry->classId);
		  }
          else
		  {
              sprintf(devname, "eth%u:%u", ifEntry->classId, ifEntry->enumerated - 1);
		  }
          ifEntry->enumerated++;
          break;
      case MIB_IF_TYPE_PPP:
          if(ifEntry->enumerated == 0)
		  {
              ifEntry->classId = pppId++;
              sprintf(devname, "ppp%u", ifEntry->classId);
		  }
          else
		  {
              sprintf(devname, "ppp%u:%u", ifEntry->classId, ifEntry->enumerated - 1);
		  }
          ifEntry->enumerated++;
          break;
      case MIB_IF_TYPE_SLIP:
          if(ifEntry->enumerated == 0)
		  {
              ifEntry->classId = slpId++;
              sprintf(devname, "slp%u", ifEntry->classId);
		  }
          else
		  {
              sprintf(devname, "slp%u:%u", ifEntry->classId, ifEntry->enumerated - 1);
		  }
          ifEntry->enumerated++;
          break;
      case MIB_IF_TYPE_LOOPBACK:
          strcpy(devname, "lo");
          break;
      default:
          continue;
      }
      if(addr.s_addr==ipt->table[ip_cnt].dwAddr)
      {
          FirstTime=0;
          return strdup(devname);
      }
  }
  return NULL;
}


u_long lft_getifaddr (const char *ifname)
{
    switch(VerifyWindowsVersion())
    {
    case KWV_95:
        return lft_getifaddr_95(ifname);
    case KWV_2K:
	case KWV_VISTA:
        return lft_getifaddr_2K(ifname);
    case KWV_NT4:
        return lft_getifaddr_NT4(ifname);
    }
    return -1;
}

char * lft_getifname (struct in_addr addr)
{
    static char ifname[256];
    static struct in_addr savedaddr;
    static int FirstTime=1;
    char * ret;
    if(!FirstTime && savedaddr.s_addr==addr.s_addr)
    {
        return strdup(ifname);
    }
    switch(VerifyWindowsVersion())
    {
    case KWV_95:
        ret=lft_getifname_95(addr);
        break;
    case KWV_2K:
	case KWV_VISTA:
        ret=lft_getifname_2K(addr);
        break;
    case KWV_NT4:
        ret=lft_getifname_NT4(addr);
        break;
    }
    savedaddr.s_addr=addr.s_addr;
    FirstTime=0;
    strncpy(ifname,ret,255);
	return ret;
}



#ifdef	LFT_IFADDR_TESTING
extern int
main (int argc, char *argv[])
{
	struct in_addr		in;
	char			*addr;

	if (argc > 1)
		addr = strdup (argv[1]);
	else
		addr = strdup ("eth0");

	in.s_addr = lft_getifaddr (addr);
	if (in.s_addr == -1) {
		fprintf (stderr, "%s: Error reading ifname\n", addr);
		fflush (stderr);
		free(addr);
		exit (-1);
	}

	fprintf (stdout, "%s: %s\n", addr,
		inet_ntoa (in));
	fflush (stdout);
	free (addr);
	exit (0);
}

#endif /*LFT_IFNAME_TESTING*/
#endif
