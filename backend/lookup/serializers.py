from rest_framework import serializers


class LookupRequestSerializer(serializers.Serializer):
    # The frontend only sends one string value, which keeps the request easy to understand.
    value = serializers.CharField(max_length=2048, allow_blank=False)

    def validate_value(self, value):
        cleaned_value = value.strip()

        if not cleaned_value:
            raise serializers.ValidationError("Please enter an IP address, domain, URL, or hostname.")

        return cleaned_value
