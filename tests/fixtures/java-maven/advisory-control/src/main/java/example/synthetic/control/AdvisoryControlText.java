package example.synthetic.control;

import org.apache.commons.text.StringEscapeUtils;

// [01] The module's 1.10.0 declaration is a CVE-2022-42889 version non-match only.
public final class AdvisoryControlText {
    private AdvisoryControlText() {
    }

    public static String syntheticLabel() {
        // [02] fixture:control-benign-call; not a claim that this component has no other CVEs.
        return StringEscapeUtils.escapeHtml4("Synthetic <control>");
    }
}
