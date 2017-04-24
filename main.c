/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

  unsigned char buff1[BUFFSIZE]; // buffer de recepcao

  int sockd;
  int on;
  struct ifreq ifr;
  
  int totalPackets = 0;
  int arpPackets, ipv4Packets, ipv6Packets, icmpPackets, icmpv6Packets, tcpPackets, udpPackets;
  //Criar uma struct para guardar um ip e a quantidade de vezes que o mesmo transmitiu/recebeu
  //Criar um array dessas structs para poder fazer a comparação das quantidades
  struct ipTran {
	char ip[];
	int qtd;
  }
  struct ipTran endIpMaisTran[];

int main(int argc,char *argv[])
{
    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "enp4s0");
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		totalPackets += 1;
		// impress?o do conteudo - exemplo Endereco Destino e Endereco Origem
		printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
		printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);
        int type = (buff1[12] << 8) | buff1[13];
        //printf("Tipo: %x %x -- %i \n", buff1[12], buff1[13], type);

		switch(type) {
			case 0x0800:
				ipv4Packets++;
				printf(">IPV4");

				//14 Verção
				printf("\n -VERSÃO: %i ", buff1[14] >> 4);

				//15 IHL
				int ipIHL = buff1[14] & 0x0F;
				printf("\n -IHL: %i ", buff1[14] & 0x0F);

				int ipType = buff1[15];
				printf("\n -TIPO: %i ", ipType);

				int ipLenght = (buff1[16] << 8) | buff1[17];
				printf("\n -TAMANHO: %i ", ipLenght);

				int ipIdentification = (buff1[18] << 8) | buff1[19];
				printf("\n -IDENTIFICAÇÃO: %i ", ipIdentification);

				int ipFlag = buff1[20] >> 5;
				printf("\n -FLAG: %i ", ipFlag);

				int ipFlagOffset = (buff1[20] & 0x1F) << 8 | buff1[21];
				printf("\n -FLAG OFFSET: %i ", ipFlagOffset);

				printf("\n -TTL: %i ", buff1[22]);

				int ipProtocol = buff1[23];
				printf("\n -PROTOCOL: %i ", buff1[23]);

				int ipHeaderChecksum = (buff1[24] << 8) | buff1[25];
				printf("\n -CHECKSUM: %i ", ipHeaderChecksum);

				printf("\n -IP ORIGEM: %i.%i.%i.%i ", buff1[26],buff1[27],buff1[28],buff1[29]);
				printf("\n -IP DESTINO: %i.%i.%i.%i ", buff1[30],buff1[31],buff1[32],buff1[33]);

				if (ipIHL != 5) {
					printf("\n -HAS OPTIONS");		
				}
				printf("\n");

				switch(ipProtocol){
					case 1: 
						icmpPackets++;
						printf("\n  >ICMP #########################################################################################################");
						//TAMANHO CABECALHO ETHERNET + CABECALHO IP
						int icmpInit = 14 + (ipIHL * 4);

						printf("\n  -TIPO: %i", buff1[icmpInit]);

						printf("\n  -CODIGO: %i", buff1[icmpInit + 1]);

						int icmpChecksum = (buff1[icmpInit + 2] << 8) | buff1[icmpInit + 3];
						printf("\n  -CHECKSUM: %i", icmpChecksum);
						printf("\n");
						break;
					case 6:
						tcpPackets++;
						printf("\n  >TCP #########################################################################################################");
						int tcpInit = 14 + (ipIHL * 4);

						int tcpSourcePort = (buff1[tcpInit] << 8) | buff1[tcpInit + 1];
						printf("\n  -SOURCE PORT: %i", tcpSourcePort);

						int tcpDestinationPort = (buff1[tcpInit + 2] << 8) | buff1[tcpInit + 3];
						printf("\n  -SOURCE PORT: %i", tcpSourcePort);

						long tcpSequenceNumber = (buff1[tcpInit + 4] << 24) | (buff1[tcpInit + 5] << 16) | (buff1[tcpInit + 6] << 8) | buff1[tcpInit + 7];
						printf("\n  -NUMERO DE SEQUENCIA: %ld", tcpSequenceNumber);

						long tcpAcknowledgeNumber = (buff1[tcpInit + 8] << 24) | (buff1[tcpInit + 9] << 16) | (buff1[tcpInit + 10] << 8) | buff1[tcpInit + 11];
						printf("\n  -NUMERO DO CONHECIMENTO: %ld", tcpAcknowledgeNumber);

						printf("\n  -OFFSET: %i ", buff1[tcpInit + 12] >> 4);

						printf("\n  -RESERVADO: %i ", buff1[tcpInit + 12] & 0x0F);

						printf("\n  -FLAGS: %i ", buff1[tcpInit + 13]);

						int tcpWindow = (buff1[tcpInit + 13] << 8) | buff1[tcpInit + 14];
						printf("\n  -WINDOW: %i", tcpWindow);

						int tcpChecksun = (buff1[tcpInit + 15] << 8) | buff1[tcpInit + 16];
						printf("\n  -CHECKSUN: %i", tcpChecksun);

						int tcpUrgentPointer = (buff1[tcpInit + 17] << 8) | buff1[tcpInit + 18];
						printf("\n  -URGENT POINTER: %i", tcpUrgentPointer);

						printf("\n");
						break;

					case 17:
						udpPackets++;
						printf("\n  >UDP #########################################################################################################");
						int udpInit = 14 + (ipIHL * 4);

						int udpSourcePort =  (buff1[udpInit] << 8) | buff1[udpInit + 1];
						printf("\n  -SOURCE PORT: %i", udpSourcePort);

						int udpDestinationPort = (buff1[udpInit + 2] << 8) | buff1[udpInit + 3];
						printf("\n  -DESTINATION PORT: %i", udpDestinationPort);

						int updLenght = (buff1[udpInit + 4] << 8) | buff1[udpInit + 5];
						printf("\n  -TAMANHO: %i", updLenght);

						int updChecksun = (buff1[udpInit + 6] << 8) | buff1[udpInit + 7];
						printf("\n  -CHECKSUN: %i", updChecksun);
						printf("\n");
						break;
				}

				printf("\n");
				break;	
			case 0x0806:
			arpPackets++;
				printf(">ARP ");
				//14 Primeiro
				int aprHardwareAddressType = (buff1[14] << 8) | buff1[15];
				printf("\n -TIPO DE ENDERECO DE HARDWARE: %i", aprHardwareAddressType);

				int aprProtocolAddressType = (buff1[16] << 8) | buff1[17];
				printf("\n -TIPO DE ENDERECO DE PROTOCOLO: %i", aprProtocolAddressType);

				printf("\n -TAMANHO DO ENDERECO DE HARDWARE: %i", buff1[18]);

				printf("\n -TAMANHO DO ENDERECO DE PROTOCOLO: %i", buff1[19]);

				int aprOperation = (buff1[20] << 8) | buff1[21];
				printf("\n -OPERACAO: %i", aprOperation);

				printf("\n -ENDERECO DE HARDWARE DA ORIGEM: %x:%x:%x:%x:%x:%x", buff1[22],buff1[23],buff1[24],buff1[25],buff1[26],buff1[27]);

				printf("\n -ENDERECO DE PROTOCOLO DE ORIGEM: %i.%i.%i.%i ", buff1[28],buff1[29],buff1[30],buff1[31]);
				
				printf("\n -ENDERECO DE HARDWARE DO DESTINO: %x:%x:%x:%x:%x:%x", buff1[32],buff1[33],buff1[34],buff1[35],buff1[36],buff1[37]);

				printf("\n -ENDERECO DE PROTOCOLO DE DESTINO: %i.%i.%i.%i ", buff1[38],buff1[39],buff1[40],buff1[41]);

				printf("\n");
				break;
			case 0x86DD:
				ipv6Packets++;
				printf("IPV6");

				printf("\n VERSION: %i", buff1[14] >> 4);
				
				int ipv6TrafficClass = (((buff1[14] & 0x0F) << 4) | (buff1[15] >> 4));
				printf("\n TRAFFIC CLASS: %i", ipv6TrafficClass);

				int ipv6FlowLabel = ( ((buff1[15] & 0x0F) << 16) | (buff1[16] << 8) | buff1[17] );
				printf("\n FLOW LABEL: %i", ipv6FlowLabel);
				
				int ipv6PayloadLength = ( (buff1[18] << 8) | (buff1[19]) );
				printf("\n PAYLOAD LENGTH: %i", ipv6PayloadLength);
				
				int ipv6NextHeader = (buff1[20]);
				switch(ipv6NextHeader){
					case 6:
						tcpPackets++;
						printf("\n NEXT HEADER: %i (TCP)", ipv6NextHeader);
						break;

					case 17:
						udpPackets++;
						printf("\n NEXT HEADER: %i (UDP)", ipv6NextHeader);
						break;

					case 58:
						icmpv6Packets++;
						printf("\n NEXT HEADER: %i (ICMPv6) #################\n", ipv6NextHeader);
						
						int icmpv6Type = buff1[54];
						printf("\n ICMPv6 TYPE: %i", icmpv6Type);
						
						int icmpv6Code = buff1[55];
						printf("\n ICMPv6 CODE: %i", icmpv6Code);
						
						int icmpv6CheckSum = (buff1[56] << 8) | buff1[57];
						printf("\n CHECKSUM: %i", icmpv6CheckSum);
						
						switch(icmpv6Type){
							case 1:
								switch(icmpv6Code){
									case 0:
										printf("\n no route to destination");
										break;

									case 1:
										printf("\n communication administratively prohibited");
										break;

									case 2:
										printf("\n (not assigned)");
										break;

									case 3:
										printf("\n address unreachable");
										break;

									case 4:
										printf("\n port unreachable");
										break;
								}
								break;

							case 2:
								printf("\n packet too big message");
								break;

							case 3:
								switch(icmpv6Code){
									case 0:
										printf("\n hop limit sxceeded in transit");
										break;

									case 1:
										printf("\n fragment reassembly time exceeded");
										break;
								}
								break;

							case 4:
								switch(icmpv6Code){
									case 0:
										printf("\n erroneous header field encountered");
										break;

									case 1:
										printf("\n unrecognized 'Next Header' type encountered");
										break;

									case 2:
										printf("\n unrecognized IPv6 option encountered");
										break;
								}
								break;

							case 128:
								printf("\n echo request");
								break;

							case 129:
								printf("\n echo reply");
								break;
						}
						
						break;
				}

				int ipv6HopLimit = (buff1[21]);
				printf("\n HOP LIMIT: %i", ipv6HopLimit);

				printf("\n SOURCE ADDRESS: %x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
					buff1[22],buff1[23],buff1[24],buff1[25],buff1[26],buff1[27],buff1[28],buff1[29],
					buff1[30],buff1[31],buff1[32],buff1[33],buff1[34],buff1[35],buff1[36],buff1[37]);
				
				printf("\n DESTINATION ADDRESS: %x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
					buff1[38],buff1[39],buff1[40],buff1[41],buff1[42],buff1[43],buff1[44],buff1[45],
					buff1[46],buff1[47],buff1[48],buff1[49],buff1[50],buff1[51],buff1[52],buff1[53]);
				break;
		}
		printf("\n Total de Pacotes: %i", totalPackets);
		printf("\n Pacotes ARP: %i%"	, (arpPackets 	* 100)/totalPackets );
		printf("\n Pacotes IPv4: %i%"	, (ipv4Packets 	* 100)/totalPackets );
		printf("\n Pacotes IPv6: %i%"	, (ipv6Packets 	* 100)/totalPackets );
		printf("\n Pacotes ICMP: %i%"	, (icmpPackets 	* 100)/totalPackets );
		printf("\n Pacotes ICMPv6: %i%"	, (icmpv6Packets * 100)/totalPackets );
		printf("\n Pacotes TCP: %i%"	, (tcpPackets 	* 100)/totalPackets );
		printf("\n Pacotes UDP: %i%"	, (udpPackets 	* 100)/totalPackets );
		printf("\n");
	}
}
