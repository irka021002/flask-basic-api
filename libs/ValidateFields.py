def validate_fields(form_data, fields):
    missing_fields = [field for field in fields if field not in form_data]
    if missing_fields:
        return False, missing_fields
    return True, None