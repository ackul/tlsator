tlsator
=======
SSL Data is encapsulated using the record layer. For most of the SSL stack, a single packet would contain a full record. However, this is not true for Handshake and Application Data protocols. The SSL spec says that only if the record is greater than 2 ^ 14 bytes an exception should be raised. The TCP fragmentation limit is around 1514. Hence, any SSL record greater than 1514 would be sent in two different TCP segments. 
 
Most of the contemporary Packet Parsing libraries assume that an entire ssl record would be seen in a packet otherwise an exception is raised. 
 
TLSator aims at providing a functionality which allows the user to drop record on the fly. The idea is to see how application react on such an event.  

![alt tag](https://raw.githubusercontent.com/achinkulshrestha/tlsator/master/readme-imgs/Help.PNG)


How the analysis would look like

![alt tag](https://raw.githubusercontent.com/achinkulshrestha/tlsator/master/readme-imgs/analysis.PNG)

 


On the client side use: 
wget --debug https://<ProxyURL><Port> to verify 
wget --debug --no-check-certificate -P . -A jpeg https://<ip,port>
 
