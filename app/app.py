import socket
import csv
import time
import os
import socket
import threading
import ipaddress


# Funções auxiliares para conversão de formato pra exportar corretamente e nao em bytes
def formatar_mac(mac):
    return ':'.join('%02x' % b for b in mac)

def formatar_ip(ip):
    if len(ip) == 4:
        return str(ipaddress.IPv4Address(ip))
    elif len(ip) == 16:
        return str(ipaddress.IPv6Address(ip))
 
def formatar_porta(porta_bytes):
    porta = int.from_bytes(porta_bytes, 'big')
    try:
        #pega da biblioteca do linux quais sao os possiveis protocolos conhecidos, se nao retornar nada, é porta aleatoria
        service = socket.getservbyport(porta)
        return f"{porta} - {service.upper()}"
    except OSError:
        return f"{porta} - DESCONHECIDO"

# Cria um socket raw
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

#Tamanhos do pacote a partir de cada camada
tam_pacote_enlace = 0
tam_pacote_rede = 0
tam_pacote_transporte = 0

#Dados cabeçalho 2
cabecalho_eth = ['Data','Mac_Origem','Mac_Destino','Protocolo','Tamanho_Quadro']
mac_origem = ""
mac_destino = ""
tamanho_enlace = 14  # Ethernet tem sempre 14 bytes

#Dados Rede cabeçalho 3
cabecalho_rede = ['Data','Protocolo','IP_Origem','IP_Destino','ID_Protocolo','Tamanho_Pacote']
rede = 0
ip_origem = 0
ip_destino = 0
id_protocolo_transporte = 0
tamanho_rede = 0

#Dados Transporte cabeçalho 4
cabecalho_transporte = ['Data','Protocolo','IP_Origem','Porta_Origem','IP_Destino','Porta_Destino','Tamanho_Pacote_Transporte']
protocolo_transporte = ""
porta_origem = ""
porta_destino = ""
inicio_transporte = ""

#Contadores pra mostrar na tela
cont_IPv4 = cont_IPv6 = cont_ARP = cont_TCP = cont_UDP = cont_ICMP = cont_ICMPv6 = 0

#Flag para continuar programa
continuar_programa = True

print("PROGRAMA INICIADO")

#interface do usuario
def interface():
    global continuar_programa
    global cont_IPv4, cont_IPv6, cont_ARP, cont_TCP, cont_UDP, cont_ICMP, cont_ICMPv6

    print()
    print("Iniciando interface")
    while continuar_programa:
        print("Comandos:")
        print("q -> terminar programa")
        print("r -> mostrar relatorio atual")
        print("z -> zerar contadores")
        opcao = input("Escolha uma opção: ").lower()

        if opcao == "q":
            print("SAINDO DO PROGRAMA")
            print("===========================\n")

            continuar_programa = False
        elif opcao == "r":
            print("\n===== RELATÓRIO ATUAL =====")
            print(f"IPv4     : {cont_IPv4}")
            print(f"IPv6     : {cont_IPv6}")
            print(f"ARP      : {cont_ARP}")
            print(f"TCP      : {cont_TCP}")
            print(f"UDP      : {cont_UDP}")
            print(f"ICMP     : {cont_ICMP}")
            print(f"ICMPv6   : {cont_ICMPv6}")
            print("===========================\n")
        elif opcao == "z":
            cont_IPv4 = cont_IPv6 = cont_ARP = cont_TCP = cont_UDP = cont_ICMP = cont_ICMPv6 = 0
            print("\n===== RELATÓRIO REINICIADO =====")
            print(f"IPv4     : {cont_IPv4}")
            print(f"IPv6     : {cont_IPv6}")
            print(f"ARP      : {cont_ARP}")
            print(f"TCP      : {cont_TCP}")
            print(f"UDP      : {cont_UDP}")
            print(f"ICMP     : {cont_ICMP}")
            print(f"ICMPv6   : {cont_ICMPv6}")
            print("===========================\n")


# Cria thread da interface do usuario
threadInterface = threading.Thread(target=interface, daemon=True)
# Inicia thread da interface de usuario
threadInterface.start()

while continuar_programa:

    #pega o pacote da rede
    pacote, end = s.recvfrom(65535)
    
    #Pega o tempo de chegada do pacote
    data = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())


    ####################################### CAMADA ENLACE 14 primeiros bytes #######################################
    enlace = pacote[:14]
    mac_destino = enlace[:6]
    mac_origem = enlace[6:12]
    tipo_rede = int.from_bytes(enlace[12:14], 'big')
    
    #pego onde que é o inicio da proxima camada
    inicio_rede = tamanho_enlace  

    #pega o tamanho do pacote
    tam_pacote_enlace = len(pacote)

    ####################################### CAMADA DE REDE -> depende do tipo que vem da camada anterior #######################################
    #pega o protocolo de rede a partir do inicio de rede
    rede = pacote[inicio_rede:]
    #pega o tamanho a partir de camada rede
    tam_pacote_rede = len(rede)

    #Se for IPv4 (tem 20 bytes)
    if  tipo_rede == 0x0800:
        #tamanho e offset da proxima camada
        tamanho_rede = 20

        #busca as informacoes
        protocolo_rede = "IPv4"
        ip_origem = rede[12:16]
        ip_destino = rede[16:20]
        id_protocolo_transporte = rede[9:10]

        #atualizar contador
        cont_IPv4 += 1

    #Se for IPv6 (tem 40 bytes)    
    elif tipo_rede == 0x86DD:
        #tamanho e offset da proxima camada
        tamanho_rede = 40

        #busca as informacoes
        protocolo_rede = "IPv6"
        ip_origem = rede[8:24]
        ip_destino = rede[24:40]
        id_protocolo_transporte = rede[6:7]

        #atualizar contador
        cont_IPv6 += 1
        
    #Se for arp tem 28 bytes
    elif tipo_rede == 0x0806:
        #tamanho e offset da proxima camada
        tamanho_rede = 28

        #busca as informacoes
        protocolo_rede = "ARP"
        ip_origem = rede[14:18]
        ip_destino = rede[24:28]
        id_protocolo_transporte = b'\x00\x00'  # ARP não tem protocolo de transporte

        #atualizar contador
        cont_ARP += 1

    #pega o offset da camada de transporte
    inicio_transporte = inicio_rede + tamanho_rede
    
    ####################################### CAMADA DE TRANSPORTE -> depende do tipo que vem da camada de rede #######################################
    protocolo_transporte = pacote[inicio_transporte:]
    #pega o tamanho a partir de transporte
    tam_pacote_transporte = len(protocolo_transporte)
    
    tipo_transporte = int.from_bytes(id_protocolo_transporte, 'big')

    # Inicializa padrão para não TCP/UDP/ICMP
    nome_transporte = "OUTRO"
    porta_origem = b'\x00\x00'
    porta_destino = b'\x00\x00'
    tamanho_transporte = 0

    #se for TCP
    if tipo_transporte == 6:
        #tamanho e offset da proxima camada
        tamanho_transporte = 20

        #busca as informacoes
        nome_transporte = "TCP"
        porta_origem = protocolo_transporte[0:2]
        porta_destino = protocolo_transporte[2:4]

        #atualizar contador
        cont_TCP += 1

    #se for UDP
    elif tipo_transporte == 17:
        #tamanho e offset da proxima camada
        tamanho_transporte = 8

        #busca as informacoes
        nome_transporte = "UDP"
        porta_origem = protocolo_transporte[0:2]
        porta_destino = protocolo_transporte[2:4]

        #atualizar contador
        cont_UDP += 1

    #se for ICMP
    elif tipo_transporte == 1:
        #tamanho e offset da proxima camada
        tamanho_transporte = 8

        #busca as informacoes
        nome_transporte = "ICMP"
        porta_origem = b'\x00\x00'
        porta_destino = b'\x00\x00'

        #atualizar contador
        cont_ICMP += 1

    #se for ICMPv6
    elif tipo_transporte == 58:
        #tamanho e offset da proxima camada
        tamanho_transporte = 8

        #busca as informacoes
        nome_transporte = "ICMPv6"
        porta_origem = b'\x00\x00'
        porta_destino = b'\x00\x00'

        #atualizar contador
        cont_ICMPv6 += 1

    else:
        nome_transporte = str(tipo_transporte)

    inicio_aplicacao = inicio_transporte + tamanho_transporte

    ####################################### SALVAR OS DADOS NO CSV #######################################

    ####################################### CAMADA 2 #######################################
    #cabecalho_eth = ['Data','Mac_Origem','Mac_Destino','Protocolo','Tamanho_Pacote']
    with open('camada2.csv', 'a', newline='', encoding='utf-8') as f:
        escrever_cabecalho = not os.path.exists('camada2.csv') or os.stat('camada2.csv').st_size == 0
        writer = csv.DictWriter(f, fieldnames=cabecalho_eth)
        if escrever_cabecalho:
            writer.writeheader()
        writer.writerow({
            'Data': data,
            'Mac_Origem': formatar_mac(mac_origem),
            'Mac_Destino': formatar_mac(mac_destino),
            'Protocolo': hex(tipo_rede) + " - " + protocolo_rede,
            'Tamanho_Quadro': tam_pacote_enlace
        })

    ####################################### CAMADA 3 #######################################
    #cabecalho_rede = ['Data','Protocolo','IP_Origem','IP_Destino','ID_Protocolo','Tamanho_Pacote']
    with open('camada3.csv', 'a', newline='', encoding='utf-8') as f:
        escrever_cabecalho = not os.path.exists('camada3.csv') or os.stat('camada3.csv').st_size == 0
        writer = csv.DictWriter(f, fieldnames=cabecalho_rede)
        if escrever_cabecalho:
            writer.writeheader()
        writer.writerow({
            'Data': data,
            'Protocolo': protocolo_rede,
            'IP_Origem': formatar_ip(ip_origem),
            'IP_Destino': formatar_ip(ip_destino),
            'ID_Protocolo': tipo_transporte,
            'Tamanho_Pacote': tam_pacote_rede 
        })


    ####################################### CAMADA 4 #######################################
    #cabecalho_transporte = ['Data','Protocolo','IP_Origem','Porta_Origem','IP_Destino','Porta_Destino','Tamanho_Pacote']
    with open('camada4.csv', 'a', newline='', encoding='utf-8') as f:
        escrever_cabecalho = not os.path.exists('camada4.csv') or os.stat('camada4.csv').st_size == 0
        writer = csv.DictWriter(f, fieldnames=cabecalho_transporte)
        if escrever_cabecalho:
            writer.writeheader()
        writer.writerow({
            'Data': data,
            'Protocolo': nome_transporte,
            'IP_Origem': formatar_ip(ip_origem),
            'Porta_Origem': formatar_porta(porta_origem),
            'IP_Destino': formatar_ip(ip_destino),
            'Porta_Destino': formatar_porta(porta_destino),
            'Tamanho_Pacote_Transporte': tam_pacote_transporte 
        })

#no final, pergunta se quer excluir ou nao os resultados gerados
excluir = input("Deseja excluir os arquivos CSV gerados? (s/n): ").lower()

if excluir == "s":
    arquivos_csv = ['camada2.csv', 'camada3.csv', 'camada4.csv']
    for arquivo in arquivos_csv:
        if os.path.exists(arquivo):
            try:
                os.remove(arquivo)
                print(f"Arquivo {arquivo} removido com sucesso.")
            except Exception as e:
                print(f"Erro ao remover {arquivo}: {e}")

    print("Todos os arquivos foram excluídos. Programa encerrado.")
else:
    print("CSVs mantidos. Programa encerrado")