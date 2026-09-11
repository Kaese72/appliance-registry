package logging

import (
	"context"

	liblogger "github.com/Kaese72/huemie-lib/logging"
	"go.elastic.co/apm/v2"
)

func extractApmData(ctx context.Context) map[string]interface{} {
	labels := map[string]interface{}{}
	tx := apm.TransactionFromContext(ctx)
	if tx != nil {
		traceContext := tx.TraceContext()
		labels["trace.id"] = traceContext.Trace.String()
		labels["transaction.id"] = traceContext.Span.String()
		if span := apm.SpanFromContext(ctx); span != nil {
			labels["span.id"] = span.TraceContext().Span.String()
		}
	}
	return labels
}

func Info(msg string, ctx context.Context, data ...map[string]interface{}) {
	liblogger.Info(msg, append(data, extractApmData(ctx))...)
}

func Warn(msg string, ctx context.Context, data ...map[string]interface{}) {
	liblogger.Warn(msg, append(data, extractApmData(ctx))...)
}

func Error(msg string, ctx context.Context, data ...map[string]interface{}) {
	liblogger.Error(msg, append(data, extractApmData(ctx))...)
}

func ErrorErr(err error, ctx context.Context, data ...map[string]interface{}) {
	liblogger.ErrError(err, append(data, extractApmData(ctx))...)
}

func Fatal(msg string, ctx context.Context, data ...map[string]interface{}) {
	liblogger.Fatal(msg, append(data, extractApmData(ctx))...)
}
