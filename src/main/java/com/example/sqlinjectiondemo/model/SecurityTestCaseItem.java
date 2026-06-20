package com.example.sqlinjectiondemo.model;

public class SecurityTestCaseItem {

    private final String code;
    private final String title;
    private final String objective;
    private final String testData;
    private final String expectedResult;
    private final int points;
    private final String controlLayer;

    public SecurityTestCaseItem(String code,
                                String title,
                                String objective,
                                String testData,
                                String expectedResult,
                                int points,
                                String controlLayer) {
        this.code = code;
        this.title = title;
        this.objective = objective;
        this.testData = testData;
        this.expectedResult = expectedResult;
        this.points = points;
        this.controlLayer = controlLayer;
    }

    public String getCode() {
        return code;
    }

    public String getTitle() {
        return title;
    }

    public String getObjective() {
        return objective;
    }

    public String getTestData() {
        return testData;
    }

    public String getExpectedResult() {
        return expectedResult;
    }

    public int getPoints() {
        return points;
    }

    public String getControlLayer() {
        return controlLayer;
    }
}
