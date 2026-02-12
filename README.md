#  DHCP Rogue Server & Man-in-the-Middle
![Type](https://img.shields.io/badge/Attack-MitM-red)
![Technique](https://img.shields.io/badge/Technique-Spoofing-yellow)
![Protocol](https://img.shields.io/badge/Protocol-DHCP-blue)
![Status](https://img.shields.io/badge/Status-Educational-orange)
---

## 1. Resumen Ejecutivo
Durante la evaluación de seguridad interna en la VLAN 2295, se identificó que la red carece de mecanismos de autenticación para el servicio DHCP. Esto permitió la introducción de un **Servidor DHCP Rogue (Falso)**, logrando suplantar la puerta de enlace predeterminada (Gateway) de los clientes y exponiendo el tráfico de la red a intercepción y manipulación.

## 2. Detalles del Escenario (Topología)

El ataque se realizó en un entorno controlado simulando una red corporativa comprometida.

* **Segmento de Red:** `10.22.95.0/24`
* **VLAN Afectada:** ID 2295
* **Servidor DHCP Legítimo:** Router de Borde (`10.22.95.1`)
* **Dispositivo Atacante:** Kali Linux (`10.22.95.12`)
* **Víctima de Prueba:** PC1 (Cliente DHCP estándar)

**Diagrama de Red:**

<img width="667" height="663" alt="image" src="https://github.com/user-attachments/assets/29c12e00-48f7-4375-a73f-4e7d1dbdafc5" />


## 3. Metodología de Explotación (Proof of Concept)

Se desarrolló y ejecutó un script en Python utilizando la librería **Scapy** para explotar la condición de carrera (Race Condition) inherente al protocolo DHCP.

### Parámetros del Exploit
* **Vector de Ataque:** Man-in-the-Middle (MitM) vía DHCP Spoofing.
* **Configuración Inyectada:**
    * **IP Asignada:** `10.22.95.200`
    * **Gateway Falso:** `10.22.95.12` (Dirección del atacante).
    * **DNS Falso:** `8.8.8.8`
* **Lógica del Script:** Escucha pasiva en puerto UDP 67. Al detectar un `DHCP DISCOVER`, inyecta inmediatamente un `DHCP OFFER` malicioso antes que el servidor legítimo pueda responder. Posteriormente, confirma la transacción con un `DHCP ACK`.

### Evidencia Técnica

**Fase 1: Intercepción y Oferta Maliciosa**
El atacante detecta la solicitud de la víctima y envía la configuración falsa.

<img width="542" height="92" alt="image" src="https://github.com/user-attachments/assets/4d25ddc0-6773-410b-8425-25c370dbe6f5" />


**Fase 2: Compromiso del Cliente**
La víctima acepta la configuración del atacante. La tabla de enrutamiento muestra que el tráfico ahora fluye hacia el equipo malicioso (`10.22.95.11`) en lugar del Router real.

<img width="368" height="269" alt="image" src="https://github.com/user-attachments/assets/80310b14-986c-4da7-9422-2c7e2e38be75" />


## 4. Requisitos para Reproducción
* Acceso a la red local (Capa 2).
* Privilegios de superusuario para manipulación de puertos RAW (sockets).
* Entorno Python 3 con librerías de red instaladas.

## 5. Recomendaciones y Mitigación (Hardening)

Para remediar esta vulnerabilidad, se debe implementar **DHCP Snooping** en los switches de acceso.

**Acciones Correctivas:**
1.  Activar DHCP Snooping globalmente.
2.  Configurar los puertos de usuarios como **Untrusted** (No confiables).
3.  Configurar el puerto del Router legítimo como **Trusted** (Confiable).

```bash
! Configuración en Switch Cisco
ip dhcp snooping
ip dhcp snooping vlan 2295
interface e0/0
 description UPLINK_ROUTER
 ip dhcp snooping trust
