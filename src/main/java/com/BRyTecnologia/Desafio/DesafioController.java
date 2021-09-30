package com.BRyTecnologia.Desafio;

import com.BRyTecnologia.Desafio.model.DigitalSignature;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class DesafioController {

    private static final String FILE_PATH = "src/main/resources/arquivos/doc.txt";
    private static final String SIGNED_FILE_PATH = "src/main/resources/arquivos/signedDoc.p7s";
    private static final String KEYSTORE_FILE = "src/main/resources/pkcs12/Desafio Estagio Java.p12";
    private static final String KEYSTORE_ALIAS = "f22c0321-1a9a-4877-9295-73092bb9aa94";
    private static final char[] KEYSTORE_PWD = "123456789".toCharArray();
    private static final String OUTPUT_FILE = "src/main/resources/arquivos/output.txt";
    static final String LOCAL_TO_SAVE = "src/main/resources/arquivos/";

    @RequestMapping(method = RequestMethod.GET, path = "/signature", consumes = {
            MediaType.MULTIPART_FORM_DATA_VALUE })
    public String assinaDocumento(
            @RequestParam("fileToSign") MultipartFile fileToSign,
            @RequestParam("pfxFile") MultipartFile pfxFile,
            @RequestParam("password") String password) {
        DigitalSignature.tranferFilesToProject(fileToSign, pfxFile);
        String fileToSignPath = LOCAL_TO_SAVE + fileToSign.getOriginalFilename();
        String pfxFilePath = LOCAL_TO_SAVE + pfxFile.getOriginalFilename();
        return DigitalSignature.assinaDocumento(
                fileToSignPath,
                pfxFilePath,
                password);
    }

    @RequestMapping(method = RequestMethod.GET, path = "/verify", consumes = {
            MediaType.MULTIPART_FORM_DATA_VALUE })
    public String verificaAssinatura(
            @RequestParam("signToVerify") MultipartFile fileToSign ){
        boolean is_verified =  DigitalSignature.verifySignature(
                DigitalSignature.multipartFileToByteArray(fileToSign)
                );
        if (is_verified) {
            return "VALIDO";
        } else {
            return "INVALIDO";
        }
    }
}
