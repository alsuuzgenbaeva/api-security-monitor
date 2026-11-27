-- Phase 9 upgrade for an existing Phase 8 PostgreSQL security_event table.
-- This single DO statement is transactional: any validation failure rolls back
-- all constraint and nullability changes, leaving existing rows unchanged.
DO $phase_9_upgrade$
DECLARE
    target_table regclass := to_regclass(format('%I.%I', current_schema(), 'security_event'));
    event_type_attribute_number smallint;
    event_type_is_not_null boolean;
    event_type_data_type text;
    source_id_attribute_number smallint;
    source_id_data_type text;
    constraint_record record;
    compatible_constraint_found boolean := false;
    canonical_constraint_name constant name := 'ck_security_event_event_type_values';
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

    SELECT attribute.attnum, format_type(attribute.atttypid, attribute.atttypmod)
    INTO source_id_attribute_number, source_id_data_type
    FROM pg_attribute attribute
    WHERE attribute.attrelid = target_table
      AND attribute.attname = 'source_request_log_id'
      AND NOT attribute.attisdropped;

    IF source_id_attribute_number IS NULL THEN
        RAISE EXCEPTION 'Expected column %.security_event.source_request_log_id does not exist', current_schema();
    END IF;
    IF source_id_data_type <> 'bigint' THEN
        RAISE EXCEPTION
            'Unexpected security_event.source_request_log_id mapping: type %. Expected bigint',
            source_id_data_type;
    END IF;

    FOR constraint_record IN
        SELECT constraint_entry.conname, pg_get_constraintdef(constraint_entry.oid) AS definition
        FROM pg_constraint constraint_entry
        WHERE constraint_entry.conrelid = target_table
          AND constraint_entry.contype = 'c'
          AND constraint_entry.conkey = ARRAY[event_type_attribute_number]::smallint[]
    LOOP
        IF position('EXCESSIVE_REQUESTS' IN constraint_record.definition) > 0
                AND position('XSS_ATTEMPT' IN constraint_record.definition) > 0
                AND position('SQL_INJECTION_ATTEMPT' IN constraint_record.definition) > 0 THEN
            IF position('BRUTE_FORCE_ATTEMPT' IN constraint_record.definition) > 0 THEN
                compatible_constraint_found := true;
            ELSE
                EXECUTE format(
                        'ALTER TABLE %s DROP CONSTRAINT %I',
                        target_table,
                        constraint_record.conname);
            END IF;
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
                'Constraint % already exists but is not the expected Phase 8 event_type check',
                canonical_constraint_name;
        END IF;

        EXECUTE format(
                'ALTER TABLE %s ADD CONSTRAINT %I CHECK (event_type IN (%L, %L, %L, %L)) NOT VALID',
                target_table,
                canonical_constraint_name,
                'EXCESSIVE_REQUESTS',
                'XSS_ATTEMPT',
                'SQL_INJECTION_ATTEMPT',
                'BRUTE_FORCE_ATTEMPT');
        EXECUTE format(
                'ALTER TABLE %s VALIDATE CONSTRAINT %I',
                target_table,
                canonical_constraint_name);
    END IF;

    EXECUTE format(
            'ALTER TABLE %s ALTER COLUMN source_request_log_id DROP NOT NULL',
            target_table);
END
$phase_9_upgrade$;
