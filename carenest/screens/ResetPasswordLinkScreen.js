import React, { useEffect } from 'react';
import { View, Text, ActivityIndicator } from 'react-native';
import { useNavigation } from '@react-navigation/native';

const ResetPasswordLinkScreen = ({ route }) => {
  const navigation = useNavigation();

  useEffect(() => {
    // Extract the token from the route parameters
    const { token } = route.params;

    if (token) {
      // Navigate to the New Password screen with the token
      navigation.navigate('NewPassword', { token });
    }
  }, [route.params, navigation]);

  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <Text>Redirecting...</Text>
      <ActivityIndicator size="large" />
    </View>
  );
};

export default ResetPasswordLinkScreen;
