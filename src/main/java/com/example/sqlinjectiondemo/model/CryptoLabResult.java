package com.example.sqlinjectiondemo.model;

public class CryptoLabResult {

    private final String operation;
    private final String outputValue;
    private final String note;

    public CryptoLabResult(String operation, String outputValue, String note) {
        this.operation = operation;
        this.outputValue = outputValue;
        this.note = note;
    }

    public String getOperation() {
        return operation;
    }

    public String getOutputValue() {
        return outputValue;
    }

    public String getNote() {
        return note;
    }
}
