from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import LookupRequestSerializer
from .services import LookupService


class LookupAPIView(APIView):
    # This view accepts one value and returns the combined lookup result as JSON.
    def post(self, request):
        serializer = LookupRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        lookup_value = serializer.validated_data["value"]
        lookup_service = LookupService()
        result = lookup_service.lookup(lookup_value)

        return Response(result, status=status.HTTP_200_OK)
