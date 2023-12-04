/*
Keycloak Verifier. Plugin to search for vulnerabilities in Keycloak.
Copyright (C) 2023 Andre Sousa

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
*/

package org.example;

import java.io.IOException;

import java.io.FileWriter;
import java.util.Arrays;
import java.util.Iterator;

/*
    Class used to produce an output file that will be used to produce a log report
 */
public class produceReport {

    private static final String[] array = new String[25];
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
