// src/components/Products.tsx
import React from 'react';
import { View, Text, StyleSheet } from 'react-native';

const Products: React.FC = () => {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Products</Text>
      <Text>This is where you can display the products available.</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
  },
});

export default Products;
