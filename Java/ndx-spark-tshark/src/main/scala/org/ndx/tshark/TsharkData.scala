package org.ndx.tshark

case class Url(url:String)
case class Keyword(keyword:String, count:Integer)
case class DnsDataRaw(flow:String, id:Integer, isResponse: Boolean, rdata:String)
case class DnsData(flow:String, id:Integer, isResponse: Boolean, domain:String,
                   recordType:String, dnsClass:String, rdata:String)
case class FlowStatistics(first:java.sql.Date, last:java.sql.Date, protocol:String, srcAddr:String,
                          srcPort:String, dstAddr:String, dstPort:String, service:String, direction:String,
                          packets:Integer, octets:Long)
