/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.tomcat.jni;

import java.io.File;

/** Library
 *
 * @author Mladen Turk
 */
public final class Library {

    /* Default library names */
    private static final String [] NAMES = {"tcnative-1", "libtcnative-1"};
    /*
     * A handle to the unique Library singleton instance.
     */
    private static Library _instance = null;

    private Library() throws Exception {
        boolean loaded = false;
        String path = System.getProperty("java.library.path");
        String [] paths = path.split(File.pathSeparator);
        StringBuilder err = new StringBuilder();
        for (int i = 0; i < NAMES.length; i++) {
            try {
                System.loadLibrary(NAMES[i]);
                loaded = true;
            } catch (ThreadDeath t) {
                throw t;
            } catch (VirtualMachineError t) {
                // Don't use a Java 7 multiple exception catch so we can keep
                // the JNI code identical between Tomcat 6/7/8/9
                throw t;
            } catch (Throwable t) {
                String name = System.mapLibraryName(NAMES[i]);
                for (int j = 0; j < paths.length; j++) {
                    java.io.File fd = new java.io.File(paths[j] , name);
                    if (fd.exists()) {
                        // File exists but failed to load
                        throw t;
                    }
                }
                if (i > 0) {
                    err.append(", ");
                }
                err.append(t.getMessage());
            }
            if (loaded) {
                break;
            }
        }
        if (!loaded) {
            StringBuilder names = new StringBuilder();
            for (String name : NAMES) {
                names.append(name);
                names.append(", ");
            }
            throw new LibraryNotFoundError(names.substring(0, names.length() -2), err.toString());
        }
    }

    private Library(String libraryName)
    {
        System.loadLibrary(libraryName);
    }


    public static native void terminate();
    /* Internal function for loading APR Features */
    private static native int version(int what);

    /* TCN_MAJOR_VERSION */
    public static int TCN_MAJOR_VERSION  = 0;
    /* TCN_MINOR_VERSION */
    public static int TCN_MINOR_VERSION  = 0;
    /* TCN_PATCH_VERSION */
    public static int TCN_PATCH_VERSION  = 0;
    /* TCN_IS_DEV_VERSION */
    public static int TCN_IS_DEV_VERSION = 0;

    /* TCN_VERSION_STRING */
    public static native String versionString();

    /**
     * Setup any APR internal data structures.  This MUST be the first function
     * called for any APR library.
     * @param libraryName the name of the library to load
     *
     * @return {@code true} if the native code was initialized successfully
     *         otherwise {@code false}
     *
     * @throws Exception if a problem occurred during initialization
     */
    public static synchronized boolean initialize(String libraryName) throws Exception {
        if (_instance == null) {
            if (libraryName == null)
                _instance = new Library();
            else
                _instance = new Library(libraryName);
            TCN_MAJOR_VERSION  = version(0x01);
            TCN_MINOR_VERSION  = version(0x02);
            TCN_PATCH_VERSION  = version(0x03);
            TCN_IS_DEV_VERSION = version(0x04);

        }
        return false;
    }
}
