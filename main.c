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
		// impress�o do conteudo - exemplo Endereco Destino e Endereco Origem
		printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
		printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);
        int type = (buff1[12] << 8) | buff1[13];
        //printf("Tipo: %x %x -- %i \n", buff1[12], buff1[13], type);

		switch(type) {
			case 0x0800:
				printf("IPV4 ");

				//14 Verção
				print("VERÇÃO: %i ", buff1[14] >> 4);

				//15 IHL
				int ipIHL = buff1[14] & 0x0F;
				print("IHL: %i ", buff1[14] & 0x0F);

				int ipType = buff1[15];
				print("TIPO %i ", ipType);

				int ipLenght = (buff1[16] << 8) | buff1[17];
				print("TAMANHO: %i ", ipLenght);

				int ipIdentification = (buff1[18] << 8) | buff1[19];
				print("IDENTIFICAÇÃO: %i ", ipIdentification);

				int ipFlag = buff1[20] >> 5;
				print("FLAG: %i ", ipFlag);

				int ipFlagOffset = (buff1[20] & 0x1F) << 8 | buff1[21];
				print("FLAG OFFSET: %i ", ipFlagOffset);

				print("TTL: %i ", buff1[22]);

				print("PROTOCOL: %i ", buff1[23]);

				int ipHeaderChecksum = (buff1[24] << 8) | buff1[25];
				print("CHECKSUM: %i ", ipHeaderChecksum);

				print("IP ORIGEM: %i.%i.%i.%i ", buff1[26],buff1[27],buff1[28],buff1[29]);
				print("IP DESTINO: %i.%i.%i.%i ", buff1[30],buff1[31],buff1[32],buff1[33]);

				if (ipIHL != 5) {
					print("OPTIONS");		
				}
				print("\n");

				switch(ipType){
					case 1: 
					printf("ICMP ");
					int icmpInit = 14 + ipLenght;

					printf("TIPO: %i ", buff1[icmpInit]);

					printf("CODIGO: %i ", buff1[icmpInit + 1]);

					int icmpChecksum = (buff1[icmpInit + 2] << 8) | buff1[icmpInit + 3];
					printf("CHECKSUM: %i ", icmpChecksum);
					printf("\n");
				}

				printf("\n");
				break;	
			case 0x0806:
				print("ARP\n");
				break;
			case 0x86DD:
				print("IPV6\n");
				break;
		}
	}
}
