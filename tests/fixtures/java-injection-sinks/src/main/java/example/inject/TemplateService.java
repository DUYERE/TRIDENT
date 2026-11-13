package example.inject;

public final class TemplateService {
    private final SpelExpressionParser parser = new SpelExpressionParser();
    private final SpringTemplateEngine engine = new SpringTemplateEngine();

    public void evaluate(String expression) {
        // fixture:template-spel
        parser.parseExpression(expression);
    }

    public void render(String template) {
        // fixture:template-engine
        engine.process(template, null);
    }
}
