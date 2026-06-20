package com.example.sqlinjectiondemo.model;

public class EngineStatusSnapshot {

    private final boolean clamAvAvailable;
    private final boolean yaraAvailable;

    public EngineStatusSnapshot(boolean clamAvAvailable, boolean yaraAvailable) {
        this.clamAvAvailable = clamAvAvailable;
        this.yaraAvailable = yaraAvailable;
    }

    public boolean isClamAvAvailable() {
        return clamAvAvailable;
    }

    public boolean isYaraAvailable() {
        return yaraAvailable;
    }
}
