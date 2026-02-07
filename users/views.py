from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from .serializers import RegisterSerializer, LoginSerializer


class RegisterView(APIView):
    
    def post(self, request: Request) -> Response:
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()

            return Response(status=status.HTTP_201_CREATED)


class LoginView(APIView):

    def post(self, request: Request) -> Response:
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user = authenticate(request, username=username, password=password)
            if user:
                token = Token.objects.create(user=user)
                return Response({'token': token.key})
            else:
                return Response({'error': 'invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class ProfileView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        user = request.user
        return Response({'message': f'{user.username} profile'})
    