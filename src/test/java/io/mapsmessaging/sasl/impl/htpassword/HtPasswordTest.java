package io.mapsmessaging.sasl.impl.htpassword;

import io.mapsmessaging.sasl.NoSuchUserFoundException;
import io.mapsmessaging.sasl.impl.htpasswd.HtPasswd;
import java.util.concurrent.TimeUnit;

public class HtPasswordTest {

  public static void main(String[] args) throws NoSuchUserFoundException, InterruptedException {
    HtPasswd htPasswd = new HtPasswd("/Users/matthew/.htpassword");
    while(true){
      TimeUnit.SECONDS.sleep(1);
      try {
        System.err.println(new String(htPasswd.getPasswordHash("test")));
        System.err.println(new String(htPasswd.getPasswordHash("test2")));
      } catch (NoSuchUserFoundException e) {
      }
    }
  }

}
