package org.ndx.tshark

case class Url(url:String)

case class CipherSuite(cipherSuite:String)

case class Keyword(keyword:String, count:Integer)

case class DnsDataRaw(flow:String, id:Integer, isResponse: Boolean, record:String)

case class DnsData(flow:String, id:Integer, isResponse: Boolean, domain:String,
                   recordType:String, dnsClass:String, rdata:String)

case class DnsLatency(address:String, timeStamp:Long)

case class FlowStatistics(first:java.sql.Timestamp, last:java.sql.Timestamp, protocol:String,
                          srcAddr:String, srcPort:String, dstAddr:String, dstPort:String, service:String,
                          direction:String, packets:Integer, bytes:Long, lanWan:String, email:String)

case class TcpPacket(flow:String, timeStamp:java.sql.Timestamp, flagNS: Boolean, flagCWR: Boolean, flagECE: Boolean,
                     flagURG: Boolean, flagACK: Boolean, flagPSH: Boolean, flagRST: Boolean, flagSYN: Boolean,
                     flagFIN: Boolean, seqNo: Long, length: Integer, payload:String)
