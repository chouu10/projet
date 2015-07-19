angular.module('MyApp')
    .controller('TransfertCtrl', ['$scope', 'transfertbanc','$rootScope', function ($scope, transfertbanc,$rootScope) {

        $scope.transfert = function () {
            transfertbanc.transfert({
                num : $scope.numBank,
                methodeTransfert: $scope.MethodeTransfert,
                assocationTransfert: $scope.assocationTransfert,
                bonAchat: $scope.bonAchat
            })
        };
        $scope.pageClass = 'fadeZoo' + 'm'
    }]);