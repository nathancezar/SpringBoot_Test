package com.BRyTecnologia.Desafio;

import com.BRyTecnologia.Desafio.model.DigitalSignature;
import com.BRyTecnologia.Desafio.model.HashFile;

public class Desafio {

    private HashFile hashFile;
    private DigitalSignature digitalSignature;

    public Desafio() {
        this.hashFile = new HashFile();
        this.digitalSignature = new DigitalSignature();
    }

    public HashFile getHashFile() {
        return hashFile;
    }

    public DigitalSignature getDigitalSignature() {
        return digitalSignature;
    }
}
