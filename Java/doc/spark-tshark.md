# NDX-SPARK-XINFO

This doucment shows how to use NDX to get HTTP request information for HTTP sessions.

## Prepare data source

```scala
implicit def toConsumer[A](function: A => Unit): java.util.function.Consumer[A] = new java.util.function.Consumer[A]() {
  override def accept(arg: A): Unit = function.apply(arg)
}


import org.ndx.model.Packet;
import org.ndx.model.pcap.PacketPayload;
import org.ndx.model.pcap.PacketModel.RawFrame;
import org.ndx.model.Statistics;
import org.ndx.tshark.HttpRequest;

val frames = sc.hadoopFile("hdfs://neshpc1.fit.vutbr.cz/user/xbeder00/*.json", 
                            classOf[org.ndx.pcap.PcapInputFormat], 
                            classOf[org.apache.hadoop.io.LongWritable], 
                            classOf[org.apache.hadoop.io.ObjectWritable])
```

