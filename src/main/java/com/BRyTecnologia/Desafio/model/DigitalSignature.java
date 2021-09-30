package com.BRyTecnologia.Desafio.model;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.util.Assert;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * DigitalSignature é a classe que será usada para ler o arquivo
 * pkcs12 enviado com o desafio. Ela é responsável por obter
 * a chave privada e o certificado deste aqruivo, assinar o
 * arquivo doc.txt, verificar a assinatura e salvar a assinatura
 * no formato .p7s.
 *
 * @author Nathan Cezar Cardoso
 *
 */
public class DigitalSignature {

    /**
     * Arquivos e informações padrão do desafio
     */
    static final String FILE_PATH = "src/main/resources/arquivos/doc.txt";
    static final String SIGNED_FILE_PATH = "src/main/resources/arquivos/signedDoc.p7s";
    static final String KEYSTORE_FILE = "src/main/resources/pkcs12/Desafio Estagio Java.p12";
    static final String KEYSTORE_ALIAS = "f22c0321-1a9a-4877-9295-73092bb9aa94";
    static final char[] KEYSTORE_PWD = "123456789".toCharArray();
    static final String LOCAL_TO_SAVE = "src/main/resources/arquivos/";

    /**
     * Main para teste da classe
     */
    public static void main(String[] args) {

        try {
            KeyStore keyStoreInstance = getKeyStore(KEYSTORE_FILE, KEYSTORE_PWD);
            Assert.notNull(keyStoreInstance, "KeyStore Null.");
            PrivateKey privateKey = getPrivateKey(keyStoreInstance, KEYSTORE_ALIAS, KEYSTORE_PWD);
            Assert.notNull(privateKey, "Chave Privada Null.");
            Certificate certificate = getCertificate(keyStoreInstance, KEYSTORE_ALIAS);
            Assert.notNull(certificate, "Certificado Null.");
            byte[] data = readFileToByteArray(FILE_PATH);
            Assert.notNull(data, "Erro ao ler o arquivo " + FILE_PATH);
            byte[] signedData = signData(data, certificate, privateKey);
            Assert.notNull(signedData, "Erro ao assinar arquivo " + FILE_PATH);

            if (saveSignedData(signedData)) {
                System.out.println("Assinatura salva.");
            } else {
                throw new Exception("Erro ao salvar assinatura.");
            }
            if (verifySignature(signedData)) {
                System.out.println("assinatura verificada");
            } else {
                throw new Exception("Erro ao verificar assinatura.");
            }
        } catch (Exception e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
    }

    /**
     * Salva um array de bytes como arquivo no disco no local default SIGNED_FILE_PATH
     * @param signedData - array de bytes para ser salvo como arquivo.
     * @return True se conseguiu salvar corretamente e False caso contrário.
     */
    public static boolean saveSignedData(byte[] signedData) {
        try {
            FileOutputStream outputStream = new FileOutputStream(SIGNED_FILE_PATH);
            outputStream.write(signedData);
            outputStream.close();
            return true;
        } catch (IOException e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
        return false;
    }

    /**
     * Assina um dado usando a chave privada e o certificado
     * @param data - dado a ser assinado
     * @param certificate - certificado usado na assinatura
     * @param privateKey - chave privada usada na assinatura
     * @return Array de bytes do dado assinado.
     */
    public static byte @Nullable [] signData(
            byte[] data,
            Certificate certificate,
            PrivateKey privateKey) {

        // Código usado para adicionar o BouncyCastle como um provedor seguro
        Security.addProvider(new BouncyCastleProvider());

        // Gerador de dados assinados
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();

        // Passa o arquivo de entrada para criar um objeto tipo CMS (CMSTypeData)
        CMSTypedData cmsData = new CMSProcessableByteArray(data);

        try {
            // Classe para armazenar certificados para consulta posterior
            JcaCertStore certs = new JcaCertStore(List.of(certificate));

            // Cria um "Assinador de conteúdo" utilizando algoritmo SHA256 com RSA e a chave privada
            ContentSigner contentSigner
                    = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);

            // Adiciona o SignerInfoGenerator ao CMSSignedDataGenerator
            cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                            .build()).build(contentSigner, (X509Certificate) certificate));
            // Adiciona o certificado ao CMSSignedDataGenerator
            cmsGenerator.addCertificates(certs);

            // Gera um dado assinado que usa CSM
            CMSSignedData cms = cmsGenerator.generate(cmsData, true);

            return cms.getEncoded();

        } catch (CertificateEncodingException | OperatorCreationException | CMSException | IOException e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
        return null;
    }

    /**
     * Altera o formato do arquivo pra array de bytes, que é
     * o formato padrão usado pelo BouncyCastle
     * @param filePath - caminho para o arquivo a ser usado.
     * @return o arquivo na forma de uma array de bytes
     */
    public static byte @Nullable [] readFileToByteArray(String filePath )  {
        try {
            Path path = Path.of(filePath);
            byte[] data = Files.readAllBytes(path);
            return data;
        } catch (IOException e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
        return null;
    }

    /**
     * Verifica se o documento foi assinado
     * @param signedData - assinatura para ser verificada
     * @return retorna true se conseguiu verificar assinatura e falso caso contrário
     */
    public static boolean verifySignature(byte[] signedData ) {
        // Altera o formato do arquivo .p7s para ser usado como CMSSignedData
        ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);

        try {
            CMSSignedData cmsSignedData = new CMSSignedData(
                    ContentInfo.getInstance(asnInputStream.readObject()));

            Store<X509CertificateHolder> certificateStore = cmsSignedData.getCertificates();
            SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
            Collection<SignerInformation> signers = signerInformationStore.getSigners();
            //Itera pela coleção de informações de assinaturas para fazer a verificação
            // entre assinatura e certificado
            for (SignerInformation signer_iterator : signers) {
                Collection<?> certCollection =
                        certificateStore.getMatches(signer_iterator.getSID());

                Iterator<?> cert_iterator = certCollection.iterator();
                X509CertificateHolder certHolder = (X509CertificateHolder)cert_iterator.next();
                X509Certificate cert =
                        new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                return signer_iterator.verify(
                        new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
            }
        } catch (CertificateException | IOException | OperatorCreationException | CMSException e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
        return false;
    }

    /**
     * Lê o arquivo pkcs12 e usa para criar um objeto KeyStore
     * @param keyStoreName - caminho para o arquivo .p12
     * @param pwdArray - senha para ler o arquivo
     * @return retorna o arquivo no formato KeyStore
     */
    public static @Nullable KeyStore getKeyStore(String keyStoreName, char[] pwdArray) {
        try {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(new FileInputStream(keyStoreName), pwdArray);
            return ks;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
        return null;
    }

    /**
     * Lê do keyStore a chave privada usando o alias e a senha
     * @param ks - keyStore onde está guardada a chave privada
     * @param alias - alias do certificado
     * @param pwdArray - senha para ler o arquivo
     * @return a chave privada solicitada
     */
    public static @Nullable PrivateKey getPrivateKey (@NotNull KeyStore ks, String alias, char[] pwdArray) {
        try {
            return (PrivateKey) ks.getKey(alias, pwdArray);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
        return null;
    }

    /**
     * Lê o keyStore para obter o certificado
     * @param ks - o keyStore onde está o certificado
     * @param alias - alias do certificado
     * @return o certificado solicitado
     */
    public static @Nullable Certificate getCertificate (@NotNull KeyStore ks, String alias) {
        try {
            return ks.getCertificateChain(alias)[0];
        } catch (KeyStoreException e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
        return null;
    }

    /**
     * Lê o arquivo pfx e retorna um alias
     * @param ks - o keyStore criado com de um arquivo pfx
     * @return o alias do arquivo pfx
     */
    public static @Nullable String getAliasFromPfxFile (KeyStore ks) {
        try {
            return (String) ks.aliases().nextElement();
        } catch (KeyStoreException e) {
            System.out.println("Erro: " + e.getClass() + "Mensagem: " + e.getMessage());
        }
        return null;
    }

    /**
     * Método criado para a requisição /signature.
     * @param fileToSign - String com path do arquivo a ser assinado
     * @param pfxFile - String com path do arquivo pfx
     * @param password - String com a senha do arquivo pfx
     * @return Dado assinado no formato Base64
     */
    public static String assinaDocumento(String fileToSign, String pfxFile, String password) {
        KeyStore ks = getKeyStore(pfxFile, password.toCharArray());
        String alias = (getAliasFromPfxFile(ks));
        PrivateKey privateKey = getPrivateKey(ks, alias, password.toCharArray());
        Certificate certificate = getCertificate(ks, alias);
        byte[] data = readFileToByteArray(fileToSign);
        byte[] signedData = signData(data, certificate, privateKey);
        return Base64.getEncoder().encodeToString(signedData);
    }

    /**
     * Transforma um MultipartFile em array de bytes.
     * @param multipartFile - arquivo a ser transformado em array de bytes.
     * @return Array de bytes do arquivo.
     */
    public static byte[] multipartFileToByteArray(MultipartFile multipartFile) {
        try {
            return multipartFile.getBytes();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Transfere os arquivos enviados na requisição /signature para o root do projeto
     * @param fileToSign - arquivo a ser assinado.
     * @param pfxFile - arquivo pfx contendo a chave privada para assinatura.
     */
    public static void tranferFilesToProject(MultipartFile fileToSign, MultipartFile pfxFile) {
        Path fileToSignPath = Paths.get(LOCAL_TO_SAVE + fileToSign.getOriginalFilename());
        Path pfxFilePath = Paths.get(LOCAL_TO_SAVE + pfxFile.getOriginalFilename());
        try {
            fileToSign.transferTo(fileToSignPath);
            pfxFile.transferTo(pfxFilePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
