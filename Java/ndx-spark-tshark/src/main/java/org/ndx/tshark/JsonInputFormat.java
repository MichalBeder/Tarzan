package org.ndx.tshark;

import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.TextInputFormat;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.LineRecordReader;
import org.apache.hadoop.mapreduce.lib.input.NLineInputFormat;

import java.io.IOException;

public class JsonInputFormat extends FileInputFormat<LongWritable, Text> {
    public JsonInputFormat() {
    }

    @Override
    public RecordReader<LongWritable, Text> createRecordReader(
            InputSplit inputSplit, TaskAttemptContext taskAttemptContext) throws IOException, InterruptedException {
        String delimiter = "\n\n";
        return new LineRecordReader(delimiter.getBytes());

    }

}
