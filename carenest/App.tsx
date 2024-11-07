import React from 'react';
import { SafeAreaView, StyleSheet, Text, View, Image, TouchableOpacity } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import SignInScreen from './screens/SignInScreen';
import RegisterScreen from './screens/RegisterScreen';
import Prest from './screens/parentScreen';
import App123 from './screens/App123';
import sett from './screens/accountset';
import babypr from './screens/babyprof';
import recipe from './screens/RecipeDetailScreen';
import ForgotPasswordScreen from './screens/ForgotPasswordScreen';
import NewPasswordScreen from './screens/NewPasswordScreen';

const Stack = createStackNavigator();

// Updated linking configuration to include `10.0.2.2` for emulator access
const linking = {
  prefixes: ['yourapp://', 'https://yourapp.com', 'http://10.0.2.2:5000'],
  config: {
    screens: {
      Home: 'home',
      SignIn: 'signin',
      Register: 'register',
      ForgotPassword: 'forgot-password',
      NewPassword: {
        path: 'reset-password',
        parse: {
          token: (token) => `${token}`,
        },
      },
      App123: 'app123',
      sett: 'settings',
      babypr: 'baby-profile',
      recipe: 'recipe',
    },
  },
};

const HomeScreen = ({ navigation }) => {
  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>
          Welcome to <Text style={styles.highlightedText}>CareNest</Text>
        </Text>
        <Text style={styles.subtitle}>where your child's well-being meets peace of mind.</Text>
      </View>
      <Image source={require('./assets/baby-moon.png')} style={styles.babyImage} />
      <View style={styles.buttonsContainer}>
        <TouchableOpacity style={styles.button} onPress={() => navigation.navigate('SignIn')}>
          <Text style={styles.buttonText}>Sign In</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.button} onPress={() => navigation.navigate('Register')}>
          <Text style={styles.buttonText}>Sign Up</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
};

const App = () => {
  return (
    <NavigationContainer linking={linking}>
      <Stack.Navigator initialRouteName="Home">
        <Stack.Screen name="Home" component={HomeScreen} />
        <Stack.Screen name="SignIn" component={SignInScreen} />
        <Stack.Screen name="Register" component={RegisterScreen} />
        <Stack.Screen name="Parent" component={Prest} />
        <Stack.Screen name="ForgotPassword" component={ForgotPasswordScreen} />
        <Stack.Screen name="NewPassword" component={NewPasswordScreen} />
        <Stack.Screen name="App123" component={App123} />
        <Stack.Screen name="sett" component={sett} />
        <Stack.Screen name="babypr" component={babypr} />
        <Stack.Screen name="recipe" component={recipe} />
      </Stack.Navigator>
    </NavigationContainer>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFF3D6',
    justifyContent: 'center',
    alignItems: 'center',
  },
  header: {
    alignItems: 'center',
    marginBottom: 20,
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
  subtitle: {
    fontSize: 14,
    color: '#4C3B28',
    textAlign: 'center',
    marginTop: 5,
  },
  babyImage: {
    width: 250,
    height: 250,
    resizeMode: 'contain',
    marginVertical: 20,
  },
  buttonsContainer: {
    width: '100%',
    paddingHorizontal: 40,
    marginTop: 20,
  },
  button: {
    backgroundColor: '#F4B15E',
    paddingVertical: 15,
    borderRadius: 30,
    marginBottom: 15,
    alignItems: 'center',
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
});

export default App;
