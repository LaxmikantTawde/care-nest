import React, { useState } from 'react';
import {
  SafeAreaView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  Alert,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';

const NewPasswordScreen = ({ route }) => {
  const { token } = route.params; // Retrieve the token from the URL
  const [newPassword, setNewPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const navigation = useNavigation();

  // Password validation (minimum 6 characters)
  const validatePassword = (password) => {
    return password.length >= 6;
  };

  const handlePasswordChange = (input) => {
    setNewPassword(input);
    setPasswordError(validatePassword(input) ? '' : 'Password must be at least 6 characters');
  };

  const handleSetNewPassword = async () => {
    if (!validatePassword(newPassword)) {
      Alert.alert("Error", "Password must be at least 6 characters.");
      return;
    }

    try {
      const response = await fetch("http://10.0.2.2:5000/reset-password/" + token, {
        method: "POST",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ newPassword }),
      });
      const data = await response.json();

      if (data.success) {
        Alert.alert("Success", "Your password has been updated.");
        navigation.navigate("SignIn"); // Navigate back to SignInScreen
      } else {
        Alert.alert("Error", data.message || "Failed to reset password. Try again.");
      }
    } catch (error) {
      Alert.alert("Error", error.message || "Something went wrong");
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>Set New Password</Text>
      <TextInput
        style={styles.input}
        placeholder="New Password"
        placeholderTextColor="#B0A18C"
        secureTextEntry
        value={newPassword}
        onChangeText={handlePasswordChange}
      />
      {passwordError ? <Text style={styles.errorText}>{passwordError}</Text> : null}
      <TouchableOpacity
        style={[styles.button, { backgroundColor: newPassword && !passwordError ? '#F4B15E' : '#d3d3d3' }]}
        onPress={handleSetNewPassword}
        disabled={!newPassword || passwordError}
      >
        <Text style={styles.buttonText}>Set New Password</Text>
      </TouchableOpacity>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    padding: 16,
    backgroundColor: '#FFF3D6',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
    color: '#4C3B28',
  },
  input: {
    backgroundColor: '#FFF',
    padding: 15,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#ddd',
    marginBottom: 10,
  },
  errorText: {
    color: 'red',
    marginBottom: 10,
  },
  button: {
    paddingVertical: 15,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 10,
  },
  buttonText: {
    color: '#FFF',
    fontWeight: 'bold',
  },
});

export default NewPasswordScreen;
