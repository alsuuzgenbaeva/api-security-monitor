-- Phase 10 upgrade for an existing Phase 9 PostgreSQL security_event table.
-- This single DO statement is transactional: any validation failure rolls back
-- all column and constraint changes, leaving existing rows unchanged.
DO $phase_10_upgrade$
DECLARE
    target_table regclass := to_regclass(format('%I.%I', current_schema(), 'security_event'));
    event_type_attribute_number smallint;
    event_type_is_not_null boolean;
    event_type_data_type text;
    source_id_is_not_null boolean;
    source_id_data_type text;
    column_data_type text;
    column_is_not_null boolean;
    constraint_record record;
    literal_count integer;
    only_phase_9_values boolean;
    only_phase_10_values boolean;
    compatible_constraint_found boolean := false;
    canonical_constraint_name constant name := 'ck_security_event_event_type_values';
    phase_9_values constant text[] := ARRAY[
        'EXCESSIVE_REQUESTS',
        'XSS_ATTEMPT',
        'SQL_INJECTION_ATTEMPT',
        'BRUTE_FORCE_ATTEMPT'
    ];
    phase_10_values constant text[] := ARRAY[
        'EXCESSIVE_REQUESTS',
        'XSS_ATTEMPT',
        'SQL_INJECTION_ATTEMPT',
        'BRUTE_FORCE_ATTEMPT',
        'ENDPOINT_SCANNING',
        'ABNORMAL_ERROR_RATE'
    ];
BEGIN
    IF target_table IS NULL THEN
        RAISE EXCEPTION 'Expected table %.security_event does not exist', current_schema();
    END IF;

    SELECT attribute.attnum, attribute.attnotnull, format_type(attribute.atttypid, attribute.atttypmod)
    INTO event_type_attribute_number, event_type_is_not_null, event_type_data_type
    FROM pg_attribute attribute
    WHERE attribute.attrelid = target_table
      AND attribute.attname = 'event_type'
      AND NOT attribute.attisdropped;

    IF event_type_attribute_number IS NULL THEN
        RAISE EXCEPTION 'Expected column %.security_event.event_type does not exist', current_schema();
    END IF;
    IF event_type_data_type <> 'character varying(64)' OR NOT event_type_is_not_null THEN
        RAISE EXCEPTION
            'Unexpected security_event.event_type mapping: type %, not-null %. Expected character varying(64) NOT NULL',
            event_type_data_type, event_type_is_not_null;
    END IF;

    SELECT attribute.attnotnull, format_type(attribute.atttypid, attribute.atttypmod)
    INTO source_id_is_not_null, source_id_data_type
    FROM pg_attribute attribute
    WHERE attribute.attrelid = target_table
      AND attribute.attname = 'source_request_log_id'
      AND NOT attribute.attisdropped;

    IF source_id_data_type IS NULL THEN
        RAISE EXCEPTION 'Expected column %.security_event.source_request_log_id does not exist', current_schema();
    END IF;
    IF source_id_data_type <> 'bigint' OR source_id_is_not_null THEN
        RAISE EXCEPTION
            'Unexpected security_event.source_request_log_id mapping: type %, not-null %. Expected nullable bigint',
            source_id_data_type, source_id_is_not_null;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_attribute attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'observed_distinct_path_count'
          AND NOT attribute.attisdropped
    ) THEN
        EXECUTE format(
                'ALTER TABLE %s ADD COLUMN observed_distinct_path_count bigint',
                target_table);
    ELSE
        SELECT format_type(attribute.atttypid, attribute.atttypmod), attribute.attnotnull
        INTO column_data_type, column_is_not_null
        FROM pg_attribute attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'observed_distinct_path_count'
          AND NOT attribute.attisdropped;
        IF column_data_type <> 'bigint' OR column_is_not_null THEN
            RAISE EXCEPTION
                'Unexpected observed_distinct_path_count mapping: type %, not-null %. Expected nullable bigint',
                column_data_type, column_is_not_null;
        END IF;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_attribute attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'configured_distinct_path_threshold'
          AND NOT attribute.attisdropped
    ) THEN
        EXECUTE format(
                'ALTER TABLE %s ADD COLUMN configured_distinct_path_threshold integer',
                target_table);
    ELSE
        SELECT format_type(attribute.atttypid, attribute.atttypmod), attribute.attnotnull
        INTO column_data_type, column_is_not_null
        FROM pg_attribute attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'configured_distinct_path_threshold'
          AND NOT attribute.attisdropped;
        IF column_data_type <> 'integer' OR column_is_not_null THEN
            RAISE EXCEPTION
                'Unexpected configured_distinct_path_threshold mapping: type %, not-null %. Expected nullable integer',
                column_data_type, column_is_not_null;
        END IF;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_attribute attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'observed_client_error_count'
          AND NOT attribute.attisdropped
    ) THEN
        EXECUTE format(
                'ALTER TABLE %s ADD COLUMN observed_client_error_count bigint',
                target_table);
    ELSE
        SELECT format_type(attribute.atttypid, attribute.atttypmod), attribute.attnotnull
        INTO column_data_type, column_is_not_null
        FROM pg_attribute attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'observed_client_error_count'
          AND NOT attribute.attisdropped;
        IF column_data_type <> 'bigint' OR column_is_not_null THEN
            RAISE EXCEPTION
                'Unexpected observed_client_error_count mapping: type %, not-null %. Expected nullable bigint',
                column_data_type, column_is_not_null;
        END IF;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_attribute attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'configured_client_error_rate_percent'
          AND NOT attribute.attisdropped
    ) THEN
        EXECUTE format(
                'ALTER TABLE %s ADD COLUMN configured_client_error_rate_percent integer',
                target_table);
    ELSE
        SELECT format_type(attribute.atttypid, attribute.atttypmod), attribute.attnotnull
        INTO column_data_type, column_is_not_null
        FROM pg_attribute attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'configured_client_error_rate_percent'
          AND NOT attribute.attisdropped;
        IF column_data_type <> 'integer' OR column_is_not_null THEN
            RAISE EXCEPTION
                'Unexpected configured_client_error_rate_percent mapping: type %, not-null %. Expected nullable integer',
                column_data_type, column_is_not_null;
        END IF;
    END IF;

    FOR constraint_record IN
        SELECT constraint_entry.conname, pg_get_constraintdef(constraint_entry.oid) AS definition
        FROM pg_constraint constraint_entry
        WHERE constraint_entry.conrelid = target_table
          AND constraint_entry.contype = 'c'
          AND constraint_entry.conkey = ARRAY[event_type_attribute_number]::smallint[]
    LOOP
        SELECT count(*),
               coalesce(bool_and(matches[1] = ANY (phase_9_values)), false),
               coalesce(bool_and(matches[1] = ANY (phase_10_values)), false)
        INTO literal_count, only_phase_9_values, only_phase_10_values
        FROM regexp_matches(constraint_record.definition, '''([^'']+)''', 'g') matches;

        IF literal_count = cardinality(phase_10_values) AND only_phase_10_values THEN
            compatible_constraint_found := true;
        ELSIF literal_count = cardinality(phase_9_values) AND only_phase_9_values THEN
            EXECUTE format(
                    'ALTER TABLE %s DROP CONSTRAINT %I',
                    target_table,
                    constraint_record.conname);
        ELSIF constraint_record.definition LIKE '%EXCESSIVE_REQUESTS%'
                OR constraint_record.definition LIKE '%ENDPOINT_SCANNING%'
                OR constraint_record.definition LIKE '%ABNORMAL_ERROR_RATE%' THEN
            RAISE EXCEPTION
                'Unexpected enum-style event_type constraint %: %',
                constraint_record.conname,
                constraint_record.definition;
        END IF;
    END LOOP;

    IF NOT compatible_constraint_found THEN
        IF EXISTS (
            SELECT 1
            FROM pg_constraint constraint_entry
            WHERE constraint_entry.conrelid = target_table
              AND constraint_entry.conname = canonical_constraint_name
        ) THEN
            RAISE EXCEPTION
                'Constraint % already exists but is not the expected Phase 9 event_type check',
                canonical_constraint_name;
        END IF;

        EXECUTE format(
                'ALTER TABLE %s ADD CONSTRAINT %I CHECK (event_type IN (%L, %L, %L, %L, %L, %L)) NOT VALID',
                target_table,
                canonical_constraint_name,
                'EXCESSIVE_REQUESTS',
                'XSS_ATTEMPT',
                'SQL_INJECTION_ATTEMPT',
                'BRUTE_FORCE_ATTEMPT',
                'ENDPOINT_SCANNING',
                'ABNORMAL_ERROR_RATE');
        EXECUTE format(
                'ALTER TABLE %s VALIDATE CONSTRAINT %I',
                target_table,
                canonical_constraint_name);
    END IF;
END
$phase_10_upgrade$;
