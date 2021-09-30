package com.BRyTecnologia.Desafio.model;

import org.apache.commons.codec.digest.DigestUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.util.Assert;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * HashFile é a classe que será usada para obter o resumo criptográfico
 * de um documento, usando o algoritmo SHA256, e gerar um arquivo
 * com esse hash.
 */
public class HashFile {

    static final String FILE_PATH = "src/main/resources/arquivos/doc.txt";
    static final String OUTPUT_FILE = "src/main/resources/arquivos/output.txt";


    /**
     * Metodo Main para testar a classe
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException{

        String hexString = getFileHash(FILE_PATH);
        Assert.notNull(hexString, "Erro ao gerar o hash com getFileHash.");
        System.out.println(hexString);
        String apacheHexString = getFileHashWithApache(FILE_PATH);
        Assert.notNull(apacheHexString, "Erro ao gerar hash com getFileHashWithApache.");
        System.out.println("File Hash: " + apacheHexString);
        if (createOutputFile(OUTPUT_FILE, apacheHexString)) {
            System.out.println("Arquivo com o hash salvo.");
        } else {
            System.out.println("Erro ao salvar arquivo.");
        }
    }

    /**
     * Método que gera o hash do arquivo, usando algoritmo SHA256, usando
     * apenas a biblioteca Security do Java.
     * @param filepath - Caminho para o arquivo a ser lido
     * @return Uma string contendo o hash do arquivo em hexadecimal.
     */
    public static String getFileHash(@NotNull String filepath) {
        // Modo "manual" para converter dec para hex

        // Array de bytes para ler o arquivo em blocos
        // Usando 1024 já que o arquivo é pequeno
        byte[] buffer= new byte[1024];

        MessageDigest digest = null;
        try {
            // Objeto responsável por gerar o hash usando SHA256
            digest = MessageDigest.getInstance("SHA-256");

            // Buffer de leitura do documento
            BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(filepath));
            int count;
            while ((count = inputStream.read(buffer)) > 0) {
                digest.update(buffer, 0, count);
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Erro: " + e.getClass() + " Message " + e.getMessage());
        }

        Assert.notNull(digest, "Erro ao criar MessageDigest");
        // Array para guardar os bytes gerados pelo digest() em decimal
        byte[] hash = digest.digest();

        // Objeto mutável para usado para alterar de dec para hex
        StringBuilder sb = new StringBuilder();

        // Converte decimal para hexadecimal e adiciona ao StringBuilder
        for (byte item : hash) {
            sb.append(Integer
                    .toString((item & 0xff) + 0x100, 16)
                    .substring(1));
        }
        return sb.toString();
    }

    /**
     * Método que gera o hash do arquivo, usando algoritmo SHA256, usando
     * a biblioteca DigestUtils da Apache
     * @param filepath - Caminho para o arquivo a ser lido.
     * @return Uma String contendo o hash do arquivo em hexadecimal.
     */
    public static @Nullable String getFileHashWithApache(@NotNull String filepath) {
        try {
            Path fileName = Path.of(filepath);
            String stringFromFile = Files.readString(fileName);
            return DigestUtils.sha256Hex(stringFromFile);

        } catch (IOException e) {
            System.out.println("Erro: " + e.getClass() + " Message " + e.getMessage());
        }
        return null;
    }

    /**
     * Cria e salva um arquivo com o hash hexadecimal.
     * @param fileName - Caminho para arquivo a ser salvo.
     * @param hexString - String contendo o hash em hexadecimal.
     * @return True se conseguir salvar, false caso contrário.
     */
    public static boolean createOutputFile(String fileName, String hexString) {
        try {
            BufferedWriter br = new BufferedWriter(new FileWriter(fileName));
            br.write(hexString);
            br.close();
            return true;
        } catch (IOException e) {
            System.out.println("Erro: " + e.getClass() + " Message " + e.getMessage());
        }
        return false;
    }
}
