package com.mellivora.bamboo.logging;

/**
 * Redacts nonempty {@code securityToken=} assignment values in rendered diagnostics.
 * The ASCII field name is case-insensitive and must not follow a name character
 * (an ASCII letter, digit, underscore, hyphen, dot, percent sign, or non-ASCII
 * character). This intentionally also recognizes standalone assignments, not just
 * assignments proved to belong to a URL; an ordinary diagnostic containing such
 * an assignment is therefore redacted too.
 *
 * <p>The finite encoding contract is raw ASCII, {@code %HH}, and {@code %25HH}
 * (hexadecimal digits are case-insensitive). Each name character and the equals
 * separator may independently use any of those representations. This is not a
 * general URL decoder: plus encoding, HTML entities, Unicode escapes, and three
 * or more percent-encoding layers are not recognized. No secret value is fetched
 * or supplied, and standalone secrets without the field label are not covered.
 *
 * <p>Literal ampersands, whitespace, quotes, angle/square/round/curly brackets,
 * commas, semicolons, and fragment markers ({@code #}) end a value. Encoded forms
 * of those delimiters end it only at the separator's encoding layer (one or two).
 * For example, raw {@code securityToken=foo%26bar} has its entire value redacted,
 * whereas {@code securityToken%3Dfoo%26other%3Dbar} retains the other assignment.
 * Delimiters, labels, and all text outside matched values are preserved verbatim.
 * Malformed escapes are ordinary value text, not a reason to discard diagnostics.
 * Native URI-unreserved plaintext token values are covered; these rules do not
 * claim secrecy for arbitrary token alphabets or arbitrary renderings.
 *
 * <p>The scanner is linear with a fixed-size field match and allocates only after
 * finding a nonempty value to replace. It returns the original string otherwise.
 */
final class SecurityTokenQueryRedactor {
    private static final String FIELD = "securityToken";
    private static final String MARKER = "[REDACTED]";

    private SecurityTokenQueryRedactor() {
    }

    static String redact(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        StringBuilder result = null;
        int copiedThrough = 0;
        int previous = -1;
        int position = 0;
        while (position < text.length()) {
            int unit = unitAt(text, position);
            int character = character(unit);
            if ((character == 's' || character == 'S') && !isNameCharacter(previous)) {
                int separator = separatorAfterField(text, position);
                if (separator >= 0) {
                    int equals = unitAt(text, separator);
                    int valueStart = separator + length(equals);
                    int valueEnd = valueStart;
                    while (valueEnd < text.length()) {
                        int valueUnit = unitAt(text, valueEnd);
                        if (isDelimiter(character(valueUnit))
                                && (depth(valueUnit) == 0 || depth(valueUnit) == depth(equals))) {
                            break;
                        }
                        valueEnd += length(valueUnit);
                    }
                    if (valueEnd > valueStart) {
                        if (result == null) {
                            result = new StringBuilder(text.length());
                        }
                        result.append(text, copiedThrough, valueStart).append(MARKER);
                        copiedThrough = valueEnd;
                    }
                    position = valueEnd;
                    previous = '=';
                    continue;
                }
            }
            previous = character;
            position += length(unit);
        }
        if (result == null) {
            return text;
        }
        return result.append(text, copiedThrough, text.length()).toString();
    }

    private static int separatorAfterField(String text, int position) {
        for (int index = 0; index < FIELD.length(); index++) {
            if (position >= text.length()) {
                return -1;
            }
            int unit = unitAt(text, position);
            int actual = character(unit);
            int expected = FIELD.charAt(index);
            if (actual >= 'A' && actual <= 'Z') {
                actual += 'a' - 'A';
            }
            if (expected >= 'A' && expected <= 'Z') {
                expected += 'a' - 'A';
            }
            if (actual != expected) {
                return -1;
            }
            position += length(unit);
        }
        return position < text.length() && character(unitAt(text, position)) == '=' ? position : -1;
    }

    // Pack the decoded UTF-16 character, encoding depth, and source length into an int.
    // A second layer is precisely %25HH; do not recursively consume adjacent escapes.
    private static int unitAt(String text, int position) {
        int decoded = text.charAt(position);
        int sourceLength = 1;
        int encodingDepth = 0;
        if (decoded == '%' && position + 2 < text.length()) {
            int high = hex(text.charAt(position + 1));
            int low = hex(text.charAt(position + 2));
            if (high >= 0 && low >= 0) {
                decoded = high * 16 + low;
                sourceLength = 3;
                encodingDepth = 1;
                if (decoded == '%' && position + 4 < text.length()) {
                    high = hex(text.charAt(position + 3));
                    low = hex(text.charAt(position + 4));
                    if (high >= 0 && low >= 0) {
                        decoded = high * 16 + low;
                        sourceLength = 5;
                        encodingDepth = 2;
                    }
                }
            }
        }
        return decoded | (encodingDepth << 16) | (sourceLength << 18);
    }

    private static int character(int unit) {
        return unit & 0xffff;
    }

    private static int depth(int unit) {
        return (unit >>> 16) & 3;
    }

    private static int length(int unit) {
        return unit >>> 18;
    }

    private static int hex(char character) {
        if (character >= '0' && character <= '9') {
            return character - '0';
        }
        if (character >= 'a' && character <= 'f') {
            return character - 'a' + 10;
        }
        return character >= 'A' && character <= 'F' ? character - 'A' + 10 : -1;
    }

    private static boolean isNameCharacter(int character) {
        return character >= 'a' && character <= 'z'
                || character >= 'A' && character <= 'Z'
                || character >= '0' && character <= '9'
                || character == '_' || character == '-' || character == '.' || character == '%'
                || character > 127;
    }

    private static boolean isDelimiter(int character) {
        return Character.isWhitespace(character) || Character.isSpaceChar(character)
                || character == '&' || character == '\'' || character == '"'
                || character == '<' || character == '>' || character == '[' || character == ']'
                || character == '(' || character == ')' || character == '{' || character == '}'
                || character == ',' || character == ';' || character == '#';
    }
}
