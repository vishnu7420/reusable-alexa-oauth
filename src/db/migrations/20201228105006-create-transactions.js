'use strict';
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('transactions', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
      },
      user_id: {
        allowNull: false,
        type: Sequelize.INTEGER,
        onDelete: 'CASCADE',
        onUpdate: 'RESTRICT',
        references: {
          model: 'users',
          key: 'id'
        },
      },
      amount: {
        allowNull: false,
        type: Sequelize.STRING,
      },

      status: {
        allowNull: true,
        type: Sequelize.STRING,
      },
      gateway: {
        allowNull: true,
        type: Sequelize.STRING,
      },

      payment_gateway_trx_id: {
        allowNull: true,
        type: Sequelize.STRING,
      },

      payment_gateway_response: {
        allowNull: true,
        type: Sequelize.JSON,
      },


      payment_gateway_callback_response: {
        allowNull: true,
        type: Sequelize.JSON,
      },
      
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')


      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP')
      }
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('transactions');
  }
};

