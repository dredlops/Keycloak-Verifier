package org.example;

import java.io.IOException;

import java.io.FileWriter;
import java.util.Arrays;
import java.util.Iterator;

/*
    Class used to produce an output file that will be used to produce a log report
 */
public class produceReport {

    private static final String[] array = new String[5];
    private static FileWriter writer;
    private static int counter;

    private static final String FILE = "output.log";

    public produceReport() {
        counter = 0;
    }

    public void add(String obj) {
        array[counter++] = obj;
    }


    public void writeReport() throws IOException {
        writer = new FileWriter(FILE);
        for ( int i = 0;i < counter;i++)
            writer.write(array[i]+"\n");
        writer.close();
    }
}
