package com.example.googleotp;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@Controller
public class GoogleOtpController {


    @GetMapping("/{name}")
    public String generate(@PathVariable("name") String name, Model model){
        HashMap<String, String> map = GoogleOtpUtil.generate(name,"test");
        String key = map.get("encodedKey");

        String url = GoogleOtpUtil.getQRBarcodeURL(name, "test", key);

        model.addAttribute("encodedKey", key);
        model.addAttribute("url", url);

        model.addAttribute("name", name);
        return "index";
    }
//    DVJD2WO6NHKXOATA

    @GetMapping("/{code}/{key}")
    public @ResponseBody boolean codeCheck(@PathVariable("code") String code, @PathVariable("key") String key){
        boolean check  = GoogleOtpUtil.checkCode(code, key);
        return check;
    }
}
