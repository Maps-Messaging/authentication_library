/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.util;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ArrayHelper {

  public static char[][] jsonArrayToCharArrays(char[] jsonArray) {
    if (jsonArray == null || jsonArray.length < 2 || jsonArray[0] != '[' || jsonArray[jsonArray.length - 1] != ']') {
      throw new IllegalArgumentException("Input is not a valid JSON array of strings");
    }

    List<char[]> resultList = new ArrayList<>();
    int start = -1;
    boolean inString = false;
    boolean escape = false;

    for (int i = 1; i < jsonArray.length - 1; i++) {
      char c = jsonArray[i];
      if (escape) {
        escape = false;
      } else if (c == '\\') {
        escape = true;
      } else if (c == '"') {
        inString = !inString;
        if (inString) {
          start = i + 1;
        } else {
          resultList.add(substring(jsonArray, start, i));
        }
      }
    }

    return resultList.toArray(new char[resultList.size()][]);
  }

  public static char[] charArraysToJsonArray(List<char[]> charArrays) {
    if (charArrays == null || charArrays.isEmpty()) {
      return "[]".toCharArray();
    }

    CharArrayWriter writer = new CharArrayWriter();
    writer.append('[');
    processCharArray(charArrays, writer);
    charArrays.clear();
    writer.append(']');
    char[] response = writer.toCharArray();
    writer.reset();
    char[] reset = new char[response.length];
    clearCharArray(reset);
    try {
      writer.write(reset);
    } catch (IOException e) {
      // No need to
    }
    return response;
  }

  private static void processCharArray(List<char[]> charArrays, CharArrayWriter writer){
    for (int i = 0; i < charArrays.size(); i++) {
      if (charArrays.get(i) != null) {
        char[] working = charArrays.get(i);
        writer.append('"');
        for (char c : working) {
          if (c == '\\' || c == '"') {
            writer.append('\\');
          }
          writer.append(c);
        }
        clearCharArray(working);
        writer.append('"');
        if (i < charArrays.size() - 1) {
          writer.append(',');
        }
      }
    }
  }

  public static char[] appendCharArrays(char[]... arrays) {
    // Calculate the total length of the resulting array
    int totalLength = 0;
    for (char[] array : arrays) {
      if (array != null) {
        totalLength += array.length;
      }
    }

    // Create the resulting array
    char[] result = new char[totalLength];
    int currentIndex = 0;

    // Copy each array into the resulting array
    for (char[] array : arrays) {
      if (array != null) {
        System.arraycopy(array, 0, result, currentIndex, array.length);
        currentIndex += array.length;
      }
    }

    return result;
  }

  public static boolean startsWithIgnoreCase(char[] input, char[] prefix) {
    if (input.length < prefix.length) {
      return false;
    }
    for (int i = 0; i < prefix.length; i++) {
      if (Character.toLowerCase(input[i]) != Character.toLowerCase(prefix[i])) {
        return false;
      }
    }
    return true;
  }

  public static int parseInt(char[] input) {
    return Integer.parseInt(new String(input)); // Only convert the necessary part to String temporarily
  }

  public static int indexOf(char[] input, char ch, int start) {
    for (int i = start; i < input.length; i++) {
      if (input[i] == ch) {
        return i;
      }
    }
    return -1;
  }


  public static int indexOf(char[] input, char ch) {
    for (int i = 0; i < input.length; i++) {
      if (input[i] == ch) {
        return i;
      }
    }
    return -1;
  }


  public static char[] substring(char[] input, int start) {
    return substring(input, start, input.length);
  }

  public static char[] substring(char[] input, int start, int end) {
    if (start < 0 || end > input.length || start > end) {
      throw new IndexOutOfBoundsException("Invalid substring range");
    }
    char[] result = new char[end - start];
    System.arraycopy(input, start, result, 0, end - start);
    return result;
  }


  public static byte[] charArrayToByteArray(char[] charArray) {
    Charset charset = StandardCharsets.UTF_8;
    ByteBuffer byteBuffer = charset.encode(CharBuffer.wrap(charArray));
    byte[] byteArray = new byte[byteBuffer.remaining()];
    byteBuffer.get(byteArray);
    return byteArray;
  }

  public static char[] byteArrayToCharArray(byte[] byteArray) {
    Charset charset = StandardCharsets.UTF_8;
    CharBuffer charBuffer = charset.decode(ByteBuffer.wrap(byteArray));
    char[] charArray = new char[charBuffer.remaining()];
    charBuffer.get(charArray);
    return charArray;
  }

  public static void clearCharArray(char[] charArray) {
    if (charArray != null) {
      Arrays.fill(charArray, '\u0000');
    }
  }

  public static void clearByteArray(byte[] byteArray) {
    if (byteArray != null) {
      Arrays.fill(byteArray, (byte) 0);
    }
  }

  private ArrayHelper(){}

}
