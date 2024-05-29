package org.example.encryptdecrypt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class SampleController {

    @GetMapping("/hello")
    public String hello(){
        Map<String,Object> map = new HashMap<String,Object>();
        map.put("key1", "value1");
        map.put("key2", "value2");
        System.out.println(map);
        try {
          String encryptedMessage  =  JWEEncryption.encryptData(map.toString());
            System.out.println(encryptedMessage);
            String decryptedMessage = JWEEncryption.decryptData(encryptedMessage);
            System.out.println(decryptedMessage);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return map.toString();
    }
}
