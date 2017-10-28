package org.ndx.pcap;
import java.util.*;
import junit.framework.TestCase;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import org.ndx.model.PacketModel;
public class PcapReaderTest extends TestCase {

        ClassLoader classLoader = getClass().getClassLoader();

        public PcapReaderTest(String name) {
                super( name );
        }

        public void testReadHttpCapFile() throws Exception
        {

                InputStream inputStream = classLoader.getResourceAsStream("http.cap");
                DataInputStream dataStream = new DataInputStream(inputStream);
                PcapReader reader = new PcapReader(dataStream);
                Iterator<PacketModel.RawFrame> itr = reader.iterator();
                int count = 0;
                while(itr.hasNext()) {
                        PacketModel.RawFrame frame = itr.next();
                        count++;
                }
                assertEquals(43,count);
        }
}