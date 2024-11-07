import React, { useState, useEffect } from 'react';
import {
  SafeAreaView,
  StyleSheet,
  Text,
  View,
  TextInput,
  TouchableOpacity,
  Alert,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import AsyncStorage from "@react-native-async-storage/async-storage";

const SignInScreen = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [isFormValid, setIsFormValid] = useState(false);

  const navigation = useNavigation();

  // Email validation
  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  // Password validation (minimum 6 characters)
  const validatePassword = (password) => {
    return password.length >= 6;
  };

  useEffect(() => {
    if (!email) {
      setEmailError('Email is required');
    } else if (!validateEmail(email)) {
      setEmailError('Invalid email format');
    } else {
      setEmailError('');
    }

    if (!password) {
      setPasswordError('Password is required');
    } else if (!validatePassword(password)) {
      setPasswordError('Password must be at least 6 characters');
    } else {
      setPasswordError('');
    }

    setIsFormValid(!emailError && !passwordError && email && password);
  }, [email, password, emailError, passwordError]);

  // Handle sign-in with success alert
  const handleSignIn = async () => {
    try {
      const response = await fetch("http://10.0.2.2:5000/signin", {
        method: "POST",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await response.json();

      if (data.token) {
        await AsyncStorage.setItem('token', data.token);
        navigation.replace("App123");
      } else {
        Alert.alert("Sign-In Error", data.message || "Invalid email or password");
      }
    } catch (e) {
      Alert.alert("Sign-In Error", e.message || "Something went wrong");
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>
          Care <Text style={styles.highlightedText}>Nest</Text>
        </Text>
      </View>

      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          placeholder="Email"
          placeholderTextColor="#B0A18C"
          value={email}
          onChangeText={setEmail}
          keyboardType="email-address"
        />
        {emailError ? <Text style={styles.errorText}>{emailError}</Text> : null}
      </View>

      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          placeholder="Password"
          placeholderTextColor="#B0A18C"
          secureTextEntry={true}
          value={password}
          onChangeText={setPassword}
        />
        {passwordError ? <Text style={styles.errorText}>{passwordError}</Text> : null}
      </View>

      <TouchableOpacity
        style={[styles.button, { backgroundColor: isFormValid ? '#F4B15E' : '#d3d3d3' }]}
        onPress={handleSignIn}
        disabled={!isFormValid}
      >
        <Text style={styles.buttonText}>Sign In</Text>
      </TouchableOpacity>

      <TouchableOpacity
        onPress={() => navigation.navigate('ForgotPassword')} 
      >
        <Text style={styles.forgotPasswordText}>Forgot Password?</Text>
      </TouchableOpacity>

      <Text style={styles.newUserText}>
        New User?{' '}
        <Text
          style={styles.linkText}
          onPress={() => navigation.navigate('Register')}
        >
          Create Your Account!
        </Text>
      </Text>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFF3D6',
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 20,
  },
  header: {
    alignItems: 'center',
    marginBottom: 40,
  },
  title: {
    fontSize: 28,
    fontFamily: 'serif',
    color: '#4C3B28',
  },
  highlightedText: {
    color: '#C17848',
    fontWeight: 'bold',
  },
  inputContainer: {
    width: '100%',
    marginBottom: 20,
  },
  input: {
    borderWidth: 1,
    borderColor: '#C17848',
    borderRadius: 15,
    padding: 15,
    fontSize: 16,
    color: '#4C3B28',
    backgroundColor: '#FFF',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
    elevation: 5,
  },
  errorText: {
    color: 'red',
    fontSize: 12,
    marginTop: 5,
  },
  button: {
    paddingVertical: 15,
    borderRadius: 30,
    width: '100%',
    alignItems: 'center',
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
    elevation: 5,
  },
  buttonText: {
    color: '#FFF',
    fontSize: 18,
    fontWeight: 'bold',
  },
  forgotPasswordText: {
    color: '#C17848',
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 20,
  },
  newUserText: {
    color: '#4C3B28',
    fontSize: 14,
    marginTop: 10,
  },
  linkText: {
    color: '#C17848',
    fontWeight: 'bold',
  },
});

export default SignInScreen;
