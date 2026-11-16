package com.mellivora.bamboo.logging;

import java.util.logging.LogRecord;

import org.apache.juli.OneLineFormatter;

/** Redacts securityToken assignments after native JULI rendering, under the scanner's finite encoding contract. */
public final class QuerySafeOneLineFormatter extends OneLineFormatter {
    @Override
    public String format(LogRecord record) {
        return SecurityTokenQueryRedactor.redact(super.format(record));
    }
}
